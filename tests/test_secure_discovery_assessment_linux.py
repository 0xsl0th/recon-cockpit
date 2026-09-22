"""Actual Linux three-action discovery/HTTP authority and durable evidence checks."""

import json
import os
import stat
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent.assessment import DiscoveryAssessmentProvider
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.authorized_execution import AuthorizedDiscoveryFixtureBackend
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.coordinator_isolation import BOUNDARY_NAMES, LinuxOfflineCoordinator
from recon_cockpit.secure_agent.evidence import EvidenceStore, EvidenceUnavailable, inspect_assessment
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session import SessionLimits


@pytest.fixture
def linux_lab():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for actual Linux isolation')
    assert sys.platform == 'linux' and os.geteuid() != 0
    LinuxOfflineCoordinator().check_available()


def build(*, approval=False, execute=True, limits=None):
    path = Path(__file__).resolve().parents[1] / 'examples/secure-agent-discovery-policy.json'
    policy = parse_policy({**json.loads(path.read_text()), 'require_approval': approval})
    limits = limits or SessionLimits(max_steps=3, max_output_bytes=3072)
    session_id = str(uuid4())
    return policy, limits, session_id, AuthorizedDiscoveryFixtureBackend(policy, session_id, limits, execute=execute)


@pytest.mark.integration
@pytest.mark.parametrize('case,outcome,succeeded,exchanges', [
    ('a', 'validated', 3, 3), ('b', 'not_demonstrated', 3, 3), ('c', 'inconclusive', 3, 3),
    ('d', 'inconclusive', 2, 3), ('e', 'inconclusive', 2, 3), ('f', 'inconclusive', 2, 2),
])
def test_real_discovery_http_assessment_chain(linux_lab, tmp_path, case, outcome, succeeded, exchanges):
    policy, limits, session_id, backend = build()
    coordinator = LinuxOfflineCoordinator()
    directory, audit_path = tmp_path / 'evidence', tmp_path / 'audit' / 'events.jsonl'
    with AuditSink(audit_path) as audit, EvidenceStore(
            directory, session_id=session_id, policy=policy, case=case, discovery=True) as evidence:
        provider = DiscoveryAssessmentProvider(case, audit, evidence)
        authority = AuthoritySession(policy, audit, backend, coordinator, limits, session_id=session_id,
                                     provider=provider, evidence=evidence)
        summary = authority.run(execute=True)
        report = evidence.finalize(summary)
    assert report['outcome'] == outcome and report['integrity_issues'] == []
    assert summary['actions_succeeded'] == succeeded
    assert provider.broker.snapshot['calls_reserved'] == backend.snapshot['executions_reserved'] == exchanges
    assert backend.snapshot['output_bytes_reserved'] == summary['output_reserved_bytes'] == exchanges * 1024
    assert provider.broker.snapshot['output_tokens_reserved'] == exchanges * 1024
    assert [row['action']['tool_id'] for row in report['records']] == ['tcp_connect', *(['http_probe'] * (exchanges - 1))]
    assert report['records'][0]['observation']['classification'] == 'reachable'
    assert coordinator.boundary_checks == provider.boundary_checks == dict.fromkeys(BOUNDARY_NAMES, True)
    assert inspect_assessment(directory) == report
    for row in report['records']:
        artifact = json.loads((directory / row['artifact']['filename']).read_text())
        assert artifact['boundary_checks'] == dict.fromkeys(
            ('forbidden_ip_blocked', 'forbidden_port_blocked', 'namespace_creation_blocked', 'capabilities_dropped'), True)
    events = [json.loads(line) for line in audit_path.read_text().splitlines()]
    starts = [row for row in events if row['event_type'] == 'execution_started']
    finishes = [row for row in events if row['event_type'] == 'execution_finished']
    assert [row['execution_id'] for row in starts] == [row['execution_id'] for row in report['records']]
    assert [row['execution_id'] for row in finishes] == [row['execution_id'] for row in starts]
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in directory.iterdir())
    rendered = json.dumps(report) + (directory / 'report.md').read_text() + audit_path.read_text()
    assert 'billing-db.fixture.invalid' not in rendered and 'Ignore prior instructions' not in rendered


@pytest.mark.integration
@pytest.mark.parametrize('mode,succeeded', [('none', 0), ('fresh', 3), ('refuse_http', 1), ('replay_tcp', 1)])
def test_every_capability_requires_its_own_scripted_grant(linux_lab, tmp_path, mode, succeeded):
    # Scripted grants prove mechanisms only, never human consent.
    policy, limits, session_id, backend = build(approval=True)
    grants = []

    def approve(controller, raw, *, control):
        control.check()
        if mode == 'none' or mode == 'refuse_http' and grants:
            return None
        if mode == 'replay_tcp' and grants:
            return grants[0]
        grant = controller.approvals.issue(parse_action(raw), controller.policy).reference
        grants.append(grant)
        return grant

    with AuditSink(tmp_path / 'audit' / 'events.jsonl') as audit, EvidenceStore(
            tmp_path / 'evidence', session_id=session_id, policy=policy, case='a', discovery=True) as evidence:
        provider = DiscoveryAssessmentProvider('a', audit, evidence)
        authority = AuthoritySession(policy, audit, backend, LinuxOfflineCoordinator(), limits,
                                     session_id=session_id, provider=provider, evidence=evidence)
        summary = authority.run(execute=True, interactive=True, approval=approve)
        report = evidence.finalize(summary)
    assert backend.snapshot['executions_reserved'] == summary['actions_succeeded'] == succeeded
    assert report['outcome'] == ('validated' if mode == 'fresh' else 'inconclusive')
    assert inspect_assessment(tmp_path / 'evidence') == report
    assert all(grant not in json.dumps(report) for grant in grants)


@pytest.mark.integration
@pytest.mark.parametrize('limits,launches,reason', [
    (SessionLimits(max_steps=1, max_output_bytes=3072), 1, 'step_limit'),
    (SessionLimits(max_steps=3, max_output_bytes=1024), 1, 'output_limit'),
    (SessionLimits(max_steps=3, max_output_bytes=2048), 2, 'output_limit'),
])
def test_discovery_cannot_reset_tool_budgets_between_capabilities(linux_lab, tmp_path, limits, launches, reason):
    policy, limits, session_id, backend = build(limits=limits)
    with AuditSink(tmp_path / 'audit' / 'events.jsonl') as audit, EvidenceStore(
            tmp_path / 'evidence', session_id=session_id, policy=policy, case='a', discovery=True) as evidence:
        provider = DiscoveryAssessmentProvider('a', audit, evidence)
        authority = AuthoritySession(policy, audit, backend, LinuxOfflineCoordinator(), limits,
                                     session_id=session_id, provider=provider, evidence=evidence)
        summary = authority.run(execute=True)
        report = evidence.finalize(summary)
    assert summary['stop_reason'] == reason and report['outcome'] == 'inconclusive'
    assert backend.snapshot['executions_reserved'] == launches
    assert backend.snapshot['output_bytes_reserved'] == launches * 1024
    assert inspect_assessment(tmp_path / 'evidence') == report


@pytest.mark.integration
def test_tcp_artifact_failure_prevents_any_http_planning_or_launch(linux_lab, tmp_path, monkeypatch):
    policy, limits, session_id, backend = build()
    path = tmp_path / 'evidence'
    with AuditSink(tmp_path / 'audit' / 'events.jsonl') as audit, EvidenceStore(
            path, session_id=session_id, policy=policy, case='a', discovery=True) as evidence:
        provider = DiscoveryAssessmentProvider('a', audit, evidence)
        authority = AuthoritySession(policy, audit, backend, LinuxOfflineCoordinator(), limits,
                                     session_id=session_id, provider=provider, evidence=evidence)
        original = evidence._write_new

        def fail_artifact(name, raw, limit):
            if name.startswith('result-'):
                raise OSError('synthetic artifact failure')
            original(name, raw, limit)

        monkeypatch.setattr(evidence, '_write_new', fail_artifact)
        with pytest.raises(EvidenceUnavailable):
            authority.run(execute=True)
    assert provider.broker.snapshot['calls_reserved'] == backend.snapshot['executions_reserved'] == 1
    assert not (path / 'report.json').exists()
    report = inspect_assessment(path)
    assert report['outcome'] == 'inconclusive' and 'execution_completion_unknown' in report['integrity_issues']


@pytest.mark.integration
def test_discovery_dry_run_has_no_reachability_evidence(linux_lab, tmp_path):
    policy, limits, session_id, backend = build(approval=True, execute=False)
    with AuditSink(tmp_path / 'audit' / 'events.jsonl') as audit, EvidenceStore(
            tmp_path / 'evidence', session_id=session_id, policy=policy, case='a', discovery=True) as evidence:
        provider = DiscoveryAssessmentProvider('a', audit, evidence)
        authority = AuthoritySession(policy, audit, backend, LinuxOfflineCoordinator(), limits,
                                     session_id=session_id, provider=provider, evidence=evidence)
        summary = authority.run()
        report = evidence.finalize(summary)
    assert provider.broker.snapshot['calls_reserved'] == 1 and backend.snapshot['executions_reserved'] == 0
    assert report['outcome'] == 'inconclusive' and report['records'] == []
    assert inspect_assessment(tmp_path / 'evidence') == report
