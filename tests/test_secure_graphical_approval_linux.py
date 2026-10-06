"""Owned-display scripted input validates mechanics, never personal approval.

The test changes only the mounted helper's Tk input scheduling. Production
transport, real worker confinement, grants and launch witnesses remain intact.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os
from pathlib import Path
import sys
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import graphical_approval_isolation as graphical_runtime
from recon_cockpit.secure_agent import graphical_approval_protocol as graphical
from recon_cockpit.secure_agent import graphical_approval_worker as worker
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.approvals import ApprovalUnavailable
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.models import parse_action
from scripts.secure_agent_control_plane_demo import demo_policy

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def owned_display():
    if os.environ.get('RECON_GRAPHICAL_APPROVAL_INTEGRATION') != '1':
        pytest.skip('enable RECON_GRAPHICAL_APPROVAL_INTEGRATION under an owned Xvfb display')
    assert sys.platform == 'linux' and os.geteuid() != 0
    assert os.environ.get('DISPLAY') and os.environ.get('XAUTHORITY')


def action():
    return parse_action({'schema_version': '1', 'action_id': str(uuid4()), 'tool_id': 'http_probe',
        'target': '127.0.0.1', 'parameters': {'port': 8080, 'method': 'GET', 'path': '/',
        'timeout_seconds': 1, 'max_output_bytes': 1024}, 'rationale': 'untrusted-hidden-rationale'})


def instrument(tmp_path, monkeypatch, *, answer='approve', extra=''):
    # This source variant exists only in the native test. No test switch or
    # affirmative answer operation is present in the production service.
    script = '''
        _test_old = []
        def _test_input():
            if not window._active:
                window._root.after(10, _test_input)
                return
            if TEST_ANSWER == 'approve':
                window._entry.insert(0, window._challenge)
                window._approve_button.invoke()
            elif TEST_ANSWER == 'deny':
                window._deny_button.invoke()
            elif TEST_ANSWER == 'stale':
                if not _test_old:
                    _test_old.append(window._challenge)
                    window._entry.insert(0, window._challenge)
                    window._approve_button.invoke()
                else:
                    window._entry.insert(0, _test_old[0])
                    window._approve_button.invoke()
                    assert window._decision is None
                    window._deny_button.invoke()
            elif TEST_ANSWER == 'close':
                window._root.tk.call(window._root.protocol('WM_DELETE_WINDOW'))
            window._root.after(10, _test_input)
        window._root.after(10, _test_input)
'''.replace('TEST_ANSWER', repr(answer))
    source = Path(worker.__file__).read_text().replace('        window.warmup()\n',
        '        window.warmup()\n' + script + extra)
    mounted = tmp_path / 'scripted-graphical-reviewer.py'
    mounted.write_text(source)
    original = graphical_runtime.command
    def command(*args, **kwargs):
        argv = original(*args, **kwargs)
        index = argv.index('/app/approval_runtime/graphical_approval_worker.py')
        argv[index - 1] = str(mounted)
        return argv
    monkeypatch.setattr(graphical_runtime, 'command', command)


def test_real_graphical_review_binding_single_use_and_cleanup(tmp_path, monkeypatch):
    instrument(tmp_path, monkeypatch)
    policy, proposed = demo_policy(approval=True), action()
    control = ExecutionControl(time.monotonic() + 20)
    with LinuxApprovalService(policy, str(uuid4()), frontend='graphical_v1') as service:
        ref = service.review(proposed, policy, control=control)
        assert ref
        assert service.boundary_checks == dict.fromkeys(graphical.CHECKS, True)
        assert service.consume(ref, proposed, policy) is None
        assert service.consume(ref, proposed, policy) == 'approval_unknown_or_replayed'
        process = service._process
    assert process.poll() is not None


@pytest.mark.parametrize('answer', ['deny', 'close'])
def test_graphical_denial_or_window_close_never_issues(tmp_path, monkeypatch, answer):
    instrument(tmp_path, monkeypatch, answer=answer)
    policy = demo_policy(approval=True)
    with LinuxApprovalService(policy, str(uuid4()), frontend='graphical_v1') as service:
        ref = service.review(action(), policy, control=ExecutionControl(time.monotonic() + 15))
        assert ref is None and service.boundary_checks
    assert service._process.poll() is not None


def test_graphical_stale_phrase_cannot_approve_new_prompt(tmp_path, monkeypatch):
    instrument(tmp_path, monkeypatch, answer='stale')
    policy, proposed = demo_policy(approval=True), action()
    control = ExecutionControl(time.monotonic() + 20)
    with LinuxApprovalService(policy, str(uuid4()), frontend='graphical_v1') as service:
        ref = service.review(proposed, policy, control=control)
        assert ref and service.consume(ref, proposed, policy) is None
        assert service.review(proposed, policy, control=control) is None


@pytest.mark.parametrize('change', ['action', 'policy', 'expiry', 'worker'])
def test_graphical_changed_expired_or_other_worker_grants_fail_closed(tmp_path, monkeypatch, change):
    instrument(tmp_path, monkeypatch)
    policy = replace(demo_policy(approval=True), approval_ttl_seconds=1 if change == 'expiry' else 60)
    proposed = action()
    control = ExecutionControl(time.monotonic() + 25)
    with LinuxApprovalService(policy, str(uuid4()), frontend='graphical_v1') as service:
        ref = service.review(proposed, policy, control=control)
        assert ref
        if change == 'worker':
            with LinuxApprovalService(policy, service._session_id, frontend='graphical_v1') as other:
                assert other.review(proposed, policy, control=control)
                assert other.consume(ref, proposed, policy) == 'approval_unknown_or_replayed'
            return
        if change == 'expiry':
            time.sleep(1.05)
        result = service.consume(ref, replace(proposed, rationale='changed') if change == 'action' else proposed,
                                 replace(policy, policy_version='changed') if change == 'policy' else policy)
        assert result == {'action': 'approval_action_changed', 'policy': 'approval_policy_changed',
                          'expiry': 'approval_expired'}[change]
        assert service.consume(ref, proposed, policy) == 'approval_unknown_or_replayed'


@pytest.mark.parametrize('cancel', [False, True])
def test_graphical_wait_is_bounded_and_worker_reaped(tmp_path, monkeypatch, cancel):
    instrument(tmp_path, monkeypatch, answer='wait')
    policy = demo_policy(approval=True)
    stopped = threading.Event()
    control = ExecutionControl(time.monotonic() + (15 if cancel else 2), stopped)
    with LinuxApprovalService(policy, str(uuid4()), frontend='graphical_v1') as service:
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(service.review, action(), policy, control=control)
            if cancel:
                deadline = time.monotonic() + 8
                while service.boundary_checks is None and not pending.done() and time.monotonic() < deadline:
                    time.sleep(0.01)
                assert service.boundary_checks
                stopped.set()
            with pytest.raises(ExecutionStopped) as failure:
                pending.result(timeout=10)
            assert failure.value.reason == ('session_cancelled' if cancel else 'session_timeout')
        assert service._process.poll() is not None
        with pytest.raises(ApprovalUnavailable):
            service.review(action(), policy, control=control)


def test_real_graphical_worker_has_no_host_files_environment_or_inherited_descriptor(tmp_path, monkeypatch):
    canary = tmp_path / 'host-secret'
    canary.write_text('OWNED-HOST-CANARY')
    monkeypatch.setenv('RECON_GRAPHICAL_HOST_CANARY', 'OWNED-ENV-CANARY')
    fd = os.open(canary, os.O_RDONLY)
    os.set_inheritable(fd, True)
    instrument(tmp_path, monkeypatch, extra=(
        "        assert 'RECON_GRAPHICAL_HOST_CANARY' not in os.environ\n"
        f"        assert not os.path.exists({str(canary)!r})\n"
        "        assert not os.path.exists('/app/approval_runtime/controller.py')\n"
        "        assert not os.path.exists('/app/approval_runtime/audit.py')\n"
        "        assert not os.path.exists('/home/sloth')\n"))
    policy = demo_policy(approval=True)
    try:
        with LinuxApprovalService(policy, str(uuid4()), frontend='graphical_v1') as service:
            assert service.review(action(), policy, control=ExecutionControl(time.monotonic() + 15))
    finally:
        os.close(fd)


@pytest.mark.parametrize('malice', ['replay', 'session', 'broker', 'issue', 'reset', 'boolean',
                                    'policy', 'denied_action', 'extra_fd', 'oversized', 'duplicate'])
def test_graphical_worker_rejects_forged_messages(tmp_path, monkeypatch, malice):
    import array
    import socket
    from recon_cockpit.secure_agent import approval_protocol as protocol
    instrument(tmp_path, monkeypatch, answer='deny')
    policy, proposed = demo_policy(approval=True), action()
    with LinuxApprovalService(policy, str(uuid4()), frontend='graphical_v1') as service:
        assert service.review(proposed, policy, control=ExecutionControl(time.monotonic() + 20)) is None
        value = {'version': '1', 'broker_id': service._identity, 'session_id': service._session_id,
                 'sequence': 2, 'operation': 'review', 'action': proposed.to_dict(), 'policy_digest': policy.digest}
        if malice == 'replay':
            value['sequence'] = 1
        elif malice in {'session', 'broker'}:
            value[malice + '_id'] = str(uuid4())
        elif malice in {'issue', 'reset'}:
            value['operation'] = malice
        elif malice == 'boolean':
            value['approved'] = True
        elif malice == 'policy':
            value['policy_digest'] = '0' * 64
        elif malice == 'denied_action':
            value['action']['target'] = '127.0.0.2'
        raw = protocol.encode(value)
        if malice == 'oversized':
            raw = b'x' * (protocol.MAX_PACKET + 1)
        elif malice == 'duplicate':
            raw = b'{"version":"1",' + raw[1:]
        extra_fd = None
        try:
            if malice == 'extra_fd':
                extra_fd = os.open('/dev/null', os.O_RDONLY)
                service._channel.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [extra_fd]))])
            else:
                service._channel.send(raw)
            with pytest.raises(Exception):
                service._reply()
            deadline = time.monotonic() + 3
            while service._process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            assert service._process.poll() is not None
        finally:
            if extra_fd is not None:
                os.close(extra_fd)


def graphical_request(tmp_path):
    from recon_cockpit.secure_agent.configurable_service import ConfigurableAssessmentRequest
    return ConfigurableAssessmentRequest(
        scope_json=Path('examples/secure-agent-configurable-scope.json').read_bytes(),
        policy_json=Path('examples/secure-agent-configurable-policy.json').read_bytes(),
        assessment_dir=tmp_path / 'evidence', audit_path=tmp_path / 'audit.jsonl',
        execute=True, approval_frontend='graphical_v1')


def test_owned_four_action_workflow_uses_real_graphical_grants_and_launch_witnesses(tmp_path, monkeypatch, record_property):
    import json
    from recon_cockpit.secure_agent.configurable_service import ConfigurableAssessmentService
    from recon_cockpit.secure_agent.configurable_evidence import inspect_assessment
    from recon_cockpit.secure_agent.configurable_backend import AuthorizedConfigurableBackend
    from recon_cockpit.secure_agent.configurable_lab import ConfigurableEndpointLab
    from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
    from test_secure_fixture_launcher_linux import descendants
    from test_secure_owned_launcher_linux import assert_reaped
    instrument(tmp_path, monkeypatch)
    # Host objects cannot run a tool or start an endpoint; only the confined
    # launcher copies execute the reviewed native workflow.
    def forbidden(*args, **kwargs):
        pytest.fail('host bypass of owned execution path')
    monkeypatch.setattr(AuthorizedConfigurableBackend, 'run', forbidden)
    monkeypatch.setattr(ConfigurableEndpointLab, 'start', forbidden)
    launchers, observed, reviewers = [], set(), []
    original_launcher, original_review = LinuxFixtureLauncher.__init__, LinuxApprovalService.review
    def track_launcher(self, *args, **kwargs):
        original_launcher(self, *args, **kwargs)
        launchers.append(self)
    def track_review(self, *args, **kwargs):
        ref = original_review(self, *args, **kwargs)
        assert self._frontend == 'graphical_v1'
        assert self.boundary_checks == dict.fromkeys(graphical.CHECKS, True)
        reviewers.append(self)
        return ref
    monkeypatch.setattr(LinuxFixtureLauncher, '__init__', track_launcher)
    monkeypatch.setattr(LinuxApprovalService, 'review', track_review)
    request = graphical_request(tmp_path)
    service = ConfigurableAssessmentService(request)
    def completed(step):
        for launcher in launchers:
            process = getattr(launcher, '_process', None)
            if process is not None:
                observed.add(process.pid)
                observed.update(descendants(process.pid))
    result = service.run(on_step=completed)
    assert result['assessment_outcome'] == 'completed'
    assert result['actions_succeeded'] == 4 and len(reviewers) == 4
    metrics = result['metrics']
    assert metrics['legitimate_task_completed'] is True
    assert metrics['useful_actions_completed'] == 4 and metrics['unnecessary_refusals'] == 0
    assert metrics['actual_provider_calls'] == metrics['actual_cost_microusd'] == 0
    assert metrics['comparison_baseline'] is None and 0 <= metrics['elapsed_ms'] < 60000
    report = json.loads((request.assessment_dir / 'report.json').read_text())
    assert len(report['records']) == 4 and report['integrity_issues'] == []
    assert report['lab_closure']['status'] == 'closed'
    audit = [json.loads(line) for line in request.audit_path.read_text().splitlines()]
    assert sum(row['event_type'] == 'approval_consumed' for row in audit) == 4
    assert sum(row['event_type'] == 'execution_started' for row in audit) == 4
    requested = [row for row in audit if row['event_type'] == 'graphical_review_requested']
    finished = [row for row in audit if row['event_type'] == 'graphical_review_finished']
    assert len(requested) == len(finished) == 4
    assert all(row['outcome'] == 'grant_issued' for row in finished)
    for index, row in enumerate(requested):
        assert row['action_digest'] == finished[index]['action_digest']
        assert row['session_id'] == result['session_id'] and row['frontend'] == 'graphical_v1'
        assert not {'reference', 'approval_reference', 'answer', 'challenge'} & row.keys()
    for row in report['records']:
        artifact = json.loads((request.assessment_dir / row['artifact']['filename']).read_bytes())
        assert artifact['boundary_checks'] and all(artifact['boundary_checks'].values())
    assert all(item._closed and item._process.poll() is not None for item in launchers)
    assert all(item._closed and item._process.poll() is not None for item in reviewers)
    assert_reaped(observed)
    before = {p.name: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns) for p in request.assessment_dir.iterdir()}
    assert inspect_assessment(request.assessment_dir) == report
    assert before == {p.name: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns) for p in request.assessment_dir.iterdir()}
    record_property('scripted_test_input_not_owner_approval', True)
    record_property('useful_actions_completed', 4)
    record_property('forbidden_listening_destinations_blocked', 12)
    record_property('execution_elapsed_ms', metrics['elapsed_ms'])
    record_property('actual_provider_calls', 0)


@pytest.mark.parametrize('outcome', ['deny', 'cancel'])
def test_owned_workflow_graphical_denial_or_cancel_cannot_launch(tmp_path, monkeypatch, outcome):
    import json
    from recon_cockpit.secure_agent.configurable_service import ConfigurableAssessmentService
    from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
    instrument(tmp_path, monkeypatch, answer='deny' if outcome == 'deny' else 'wait')
    monkeypatch.setattr(LinuxFixtureLauncher, '_start', lambda *a, **k: pytest.fail('unapproved launcher started'))
    reviewers = []
    original = LinuxApprovalService.__init__
    def track(self, *args, **kwargs):
        original(self, *args, **kwargs)
        reviewers.append(self)
    monkeypatch.setattr(LinuxApprovalService, '__init__', track)
    request = graphical_request(tmp_path)
    service = ConfigurableAssessmentService(request)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(service.run)
        if outcome == 'cancel':
            deadline = time.monotonic() + 12
            while not any(item.boundary_checks for item in reviewers) and not pending.done() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert any(item.boundary_checks for item in reviewers)
            service.cancel()
        result = pending.result(timeout=30)
    assert result['assessment_outcome'] != 'completed' and result['actions_succeeded'] == 0
    assert result['metrics']['legitimate_task_completed'] is False
    assert result['metrics']['actual_provider_calls'] == result['metrics']['actual_cost_microusd'] == 0
    audit = [json.loads(line) for line in request.audit_path.read_text().splitlines()]
    assert not any(row['event_type'] in {'execution_started', 'approval_consumed'} for row in audit)
    finished = [row for row in audit if row['event_type'] == 'graphical_review_finished']
    assert len(finished) == 1
    assert finished[0]['outcome'] == ('denied' if outcome == 'deny' else 'session_cancelled')
    assert all(item._closed and item._process.poll() is not None for item in reviewers)
    if outcome == 'cancel':
        assert result['stop_reason'] == 'session_cancelled'
