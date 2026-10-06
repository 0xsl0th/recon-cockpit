"""Graphical shared-service selection; doubles provide no approval/OS evidence."""

from dataclasses import FrozenInstanceError
import json
from pathlib import Path

import pytest

from recon_cockpit.secure_agent import configurable_contract as contract
from recon_cockpit.secure_agent import configurable_service as application
from recon_cockpit.secure_agent.approvals import ApprovalUnavailable
from recon_cockpit.secure_agent.execution import ExecutionStopped
from test_secure_http_headers_cli import portable_services


def request(tmp_path, **changes):
    values = {'scope_json': Path('examples/secure-agent-configurable-scope.json').read_bytes(),
        'policy_json': Path('examples/secure-agent-configurable-policy.json').read_bytes(),
        'assessment_dir': tmp_path / 'evidence', 'audit_path': tmp_path / 'audit.jsonl'}
    values.update(changes)
    return application.ConfigurableAssessmentRequest(**values)


@pytest.mark.parametrize('frontend', [None, True, 1, [], {}, '', 'graphical', 'module.helper'])
def test_invalid_frontend_rejected_before_io(tmp_path, frontend):
    with pytest.raises(ValueError, match='invalid_assessment_approval_frontend'):
        request(tmp_path, approval_frontend=frontend)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('execute,approval', [(False, True), (False, False), (True, False)])
def test_graphical_request_requires_execution_and_approval(tmp_path, execute, approval):
    policy = json.loads(Path('examples/secure-agent-configurable-policy.json').read_bytes())
    policy['require_approval'] = approval
    with pytest.raises(ValueError, match='graphical_assessment_requires_execution_and_approval'):
        request(tmp_path, execute=execute, approval_frontend='graphical_v1',
                policy_json=contract.encode(policy))
    assert not list(tmp_path.iterdir())


def test_frontend_is_immutable_and_default_remains_terminal(tmp_path):
    assert request(tmp_path).approval_frontend == 'terminal'
    graphical = request(tmp_path, execute=True, approval_frontend='graphical_v1')
    with pytest.raises(FrozenInstanceError):
        graphical.approval_frontend = 'terminal'
    service = application.ConfigurableAssessmentService(graphical)
    assert service.snapshot()['state'] == 'ready' and service.snapshot()['live_calls_enabled'] is False
    assert not list(tmp_path.iterdir())


def test_graphical_and_terminal_interaction_cannot_be_combined(tmp_path, monkeypatch):
    monkeypatch.setattr(application.ConfigurableAssessmentService, '_run',
                        lambda *_: pytest.fail('conflicting frontends entered authority'))
    service = application.ConfigurableAssessmentService(
        request(tmp_path, execute=True, approval_frontend='graphical_v1'))
    with pytest.raises(ValueError, match='assessment_approval_frontends_conflict'):
        service.run(interactive_terminal=True)
    assert service.snapshot()['state'] == 'ready'
    assert not service._used and not list(tmp_path.iterdir())


def test_graphical_cancel_before_start_never_inspects_runtime_or_display(tmp_path, monkeypatch):
    from recon_cockpit.secure_agent import configurable_runtime, graphical_approval_isolation
    monkeypatch.setattr(configurable_runtime, 'inspect_configurable_runtime',
                        lambda *_: pytest.fail('cancelled request inspected runtime'))
    monkeypatch.setattr(graphical_approval_isolation, 'start',
                        lambda *_: pytest.fail('cancelled request opened graphical reviewer'))
    service = application.ConfigurableAssessmentService(
        request(tmp_path, execute=True, approval_frontend='graphical_v1'))
    service.cancel()
    with pytest.raises(ExecutionStopped, match='session_cancelled'):
        service.run()
    assert service.snapshot()['state'] == 'stopped' and not list(tmp_path.iterdir())


@pytest.mark.parametrize('frontend', ['terminal', 'graphical_v1'])
@pytest.mark.parametrize('review_failure', [False, True])
def test_service_routes_only_selected_review_surface_and_denial_never_launches(
        tmp_path, monkeypatch, portable_services, frontend, review_failure):
    from recon_cockpit.secure_agent import configurable_runtime
    from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
    from recon_cockpit.secure_agent.configurable_lab import ConfigurableEndpointLab

    # Metadata-only runtime double. No native invocation or result is invented;
    # a denied review must prevent any tool/runtime manifest from being used.
    monkeypatch.setattr(configurable_runtime, 'inspect_configurable_runtime',
                        lambda *_: {contract.NMAP: {'portable': True}, contract.SSH: {'portable': True}})
    monkeypatch.setattr(ConfigurableEndpointLab, 'start', lambda *_: pytest.fail('denied review started fixture'))
    opened, reviewed = [], []
    original = LinuxApprovalService.__init__

    def construct(self, *args, **kwargs):
        opened.append((self, dict(kwargs)))
        original(self, *args, **kwargs)

    def review(self, action, policy, *, control):
        reviewed.append((self._frontend, action.to_dict(), policy.require_approval))
        control.check()
        if review_failure:
            raise ApprovalUnavailable('test-only unavailable reviewer')
        return None

    def terminal_state():
        if frontend == 'graphical_v1':
            pytest.fail('graphical selection consulted terminal interactivity')
        return False

    monkeypatch.setattr(LinuxApprovalService, '__init__', construct)
    monkeypatch.setattr(LinuxApprovalService, 'review', review)
    monkeypatch.setattr(application.sys.stdin, 'isatty', terminal_state)
    monkeypatch.setattr(application.sys.stdout, 'isatty', terminal_state)
    service = application.ConfigurableAssessmentService(request(tmp_path, execute=True, approval_frontend=frontend))
    result = service.run(interactive_terminal=(frontend == 'terminal'))
    assert len(opened) == 1 and opened[0][0]._closed
    assert opened[0][1] == ({'launch_witness': True} if frontend == 'terminal'
        else {'launch_witness': True, 'frontend': 'graphical_v1'})
    assert len(reviewed) == (1 if frontend == 'graphical_v1' else 0)
    if reviewed:
        assert reviewed[0][0] == 'graphical_v1' and reviewed[0][2] is True
    assert result['actions_succeeded'] == 0 and result['assessment_outcome'] == 'incomplete'
    assert result['metrics']['legitimate_task_completed'] is False
    assert result['metrics']['actual_provider_calls'] == result['metrics']['actual_cost_microusd'] == 0
    assert not any(event['event_type'] in {'execution_started', 'approval_consumed'} for event in portable_services)
    if frontend == 'graphical_v1' and review_failure:
        assert result['stop_reason'] == 'approval_unavailable'


@pytest.mark.parametrize('failed_event', ['graphical_review_requested', 'graphical_review_finished'])
def test_graphical_audit_failure_prevents_consumption_launch_and_final_report(
        tmp_path, monkeypatch, portable_services, failed_event):
    from recon_cockpit.secure_agent import audit_isolation, approval_isolation, launcher_isolation, configurable_runtime
    from recon_cockpit.secure_agent.audit import AuditUnavailable
    from recon_cockpit.secure_agent.configurable_lab import ConfigurableEndpointLab

    monkeypatch.setattr(configurable_runtime, 'inspect_configurable_runtime',
                        lambda *_: {contract.NMAP: {'portable': True}, contract.SSH: {'portable': True}})
    opened, reviewed, attempted = [], [], []
    for module, name in ((audit_isolation, 'LinuxAuditSink'),
                         (approval_isolation, 'LinuxApprovalService'),
                         (launcher_isolation, 'LinuxFixtureLauncher')):
        kind = getattr(module, name)
        original = kind.__init__

        def construct(self, *args, _original=original, **kwargs):
            _original(self, *args, **kwargs)
            opened.append(self)

        monkeypatch.setattr(kind, '__init__', construct)

    def emit(self, event):
        attempted.append(dict(event))
        if event['event_type'] == failed_event:
            raise AuditUnavailable('test-only graphical audit failure')
        portable_services.append(dict(event))

    def review(self, action, policy, *, control):
        control.check()
        reviewed.append(action.digest)
        # A well-shaped portable reference makes the post-review audit fault
        # meaningful: it must prevent even attempting to consume that reference.
        # No real grant, approval input or witness exists in this test.
        return 'c' * 48

    def forbidden(*args, **kwargs):
        pytest.fail('failed graphical audit reached consumption or execution')

    monkeypatch.setattr(audit_isolation.LinuxAuditSink, 'emit', emit)
    monkeypatch.setattr(approval_isolation.LinuxApprovalService, 'review', review)
    monkeypatch.setattr(approval_isolation.LinuxApprovalService, 'consume', forbidden)
    monkeypatch.setattr(launcher_isolation.LinuxFixtureLauncher, 'check_available', forbidden)
    monkeypatch.setattr(launcher_isolation.LinuxFixtureLauncher, 'run', forbidden)
    monkeypatch.setattr(ConfigurableEndpointLab, 'start', forbidden)
    service = application.ConfigurableAssessmentService(
        request(tmp_path, execute=True, approval_frontend='graphical_v1'))
    with pytest.raises(AuditUnavailable):
        service.run()
    assert len(reviewed) == (0 if failed_event == 'graphical_review_requested' else 1)
    assert attempted[-1]['event_type'] == failed_event
    if failed_event == 'graphical_review_finished':
        assert attempted[-1]['outcome'] == 'grant_issued'
    assert len(opened) == 3 and all(instance._closed for instance in opened)
    assert service.snapshot()['state'] == 'failed' and service.snapshot()['result'] is None
    assert not (tmp_path / 'evidence' / 'report.json').exists()
    assert not any(event['event_type'] in {'approval_consumed', 'execution_started'} for event in attempted)
    assert 'c' * 48 not in json.dumps(attempted)
    with pytest.raises(RuntimeError, match='assessment_already_used'):
        service.run()
