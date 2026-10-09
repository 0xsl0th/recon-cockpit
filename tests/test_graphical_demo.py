"""Walkthrough entry remains plan-only by default and never supplies consent."""

import json
from pathlib import Path
import signal

import pytest

from scripts import secure_agent_graphical_demo as demo


def test_plan_only_does_not_start_service_or_create_directory(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(demo, 'ConfigurableAssessmentService', lambda *_: pytest.fail('plan started service'))
    assert demo.main(['--output-parent', str(tmp_path)]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan['mode'] == 'plan_only' and plan['personal_walkthrough_recorded'] is False
    assert len(plan['capability']['steps']) == 4
    assert plan['capability']['live_calls_enabled'] is False
    assert not list(tmp_path.iterdir())


def test_execution_requires_explicit_private_destination(tmp_path, monkeypatch):
    monkeypatch.setattr(demo, 'ConfigurableAssessmentService', lambda *_: pytest.fail('invalid invocation started service'))
    with pytest.raises(SystemExit):
        demo.main(['--execute-owned-fixtures'])
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('kind', ['symlink', 'missing', 'shared_writable'])
def test_execution_rejects_unsafe_parent(tmp_path, monkeypatch, kind):
    path = tmp_path / 'parent'
    if kind == 'symlink':
        path.symlink_to(tmp_path, target_is_directory=True)
    elif kind == 'shared_writable':
        path.mkdir()
        path.chmod(0o777)
    monkeypatch.setattr(demo, 'ConfigurableAssessmentService', lambda *_: pytest.fail('unsafe parent started service'))
    assert demo.main(['--execute-owned-fixtures', '--output-parent', str(path)]) == 1
    assert not list(tmp_path.glob('graphical-owned-*'))


def test_explicit_walkthrough_keeps_approval_required_and_restores_signal_handlers(tmp_path, monkeypatch, capsys):
    from recon_cockpit.secure_agent.models import parse_policy
    requests, cancelled = [], []
    class Service:
        def __init__(self, request):
            requests.append(request)
        def run(self):
            return {'assessment_outcome': 'incomplete'}
        def cancel(self):
            cancelled.append(True)
    monkeypatch.setattr(demo, 'ConfigurableAssessmentService', Service)
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    assert demo.main(['--execute-owned-fixtures', '--output-parent', str(tmp_path)]) == 1
    assert {number: signal.getsignal(number) for number in previous} == previous
    assert len(requests) == 1 and cancelled
    request = requests[0]
    assert request.execute is True and request.approval_frontend == 'graphical_v1'
    assert parse_policy(request.policy_json).require_approval is True
    assert request.assessment_dir.parent.stat().st_mode & 0o777 == 0o700
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert lines[0]['live_calls_enabled'] is False and lines[-1]['assessment_outcome'] == 'incomplete'
