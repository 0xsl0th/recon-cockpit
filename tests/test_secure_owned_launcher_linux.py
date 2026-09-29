"""Persistent owned lab under a confined launcher; no external provider calls."""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.discovery_contract import discovery_action
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.owned_lab import OwnedLab, AuthorizedOwnedLabBackend
from test_secure_owned_launcher import service
from test_secure_fixture_launcher_linux import instrument, descendants
from test_secure_approval_linux import terminal, scripted_review
from test_secure_launch_admission_linux import run_workflow

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_lab():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for actual owned launcher isolation')
    assert sys.platform == 'linux' and os.geteuid() != 0


def assert_reaped(observed):
    expiry = time.monotonic()+3
    while any(Path(f'/proc/{pid}').exists() for pid in observed) and time.monotonic() < expiry:
        time.sleep(0.02)
    assert observed and not any(Path(f'/proc/{pid}').exists() for pid in observed)


def test_three_actions_share_confined_lab_without_host_launch_or_namespace_handles(monkeypatch):
    monkeypatch.setattr(OwnedLab, 'start', lambda *_: pytest.fail('host owner started'))
    monkeypatch.setattr(AuthorizedOwnedLabBackend, 'run', lambda *_a, **_k: pytest.fail('host executor called'))
    launcher, policy = service()
    control = ExecutionControl(time.monotonic()+30)
    with launcher:
        for step in (1, 2, 3):
            result = launcher.run(parse_action(discovery_action('a', step)), policy, control=control)
            assert result['status'] == 'succeeded'
            assert result['owned_lab'] == {'identity': launcher.identity, 'connection_count': step, 'request_count': step-1}
            assert all(result['boundary_checks'].values())
        assert not hasattr(launcher, '_namespace_fds') and not hasattr(launcher, 'lab')
        observed = descendants(launcher._process.pid)
        assert launcher.close() == {'identity': launcher.identity, 'connection_count': 3, 'request_count': 2, 'status': 'closed'}
    assert_reaped(observed)
    other, _ = service()
    assert other.identity != launcher.identity
    other.close()


@pytest.mark.parametrize('case,outcome', [('a', 'validated'), ('b', 'not_demonstrated'), ('c', 'inconclusive'),
                                        ('d', 'inconclusive'), ('e', 'inconclusive'), ('f', 'inconclusive')])
def test_all_owned_workflow_cases_and_readonly_evidence(tmp_path, monkeypatch, capsys, terminal, case, outcome):
    original = cli.main
    monkeypatch.setattr(cli, 'main', lambda argv: original([*argv, '--isolated-launcher']))
    monkeypatch.setattr(OwnedLab, 'start', lambda *_: pytest.fail('host owner started'))
    monkeypatch.setattr(AuthorizedOwnedLabBackend, 'run', lambda *_a, **_k: pytest.fail('host executor called'))
    run_workflow(tmp_path, monkeypatch, capsys, terminal, case, outcome, '--owned-lab')
    files = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (tmp_path/'evidence').rglob('*') if p.is_file()}
    assert original(['--inspect-assessment', str(tmp_path/'evidence')]) == 0
    assert files == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in files}
    assert json.loads(capsys.readouterr().out)['integrity_issues'] == []


@pytest.mark.parametrize('fault', ['owner', 'pins', 'admission', 'completion'])
def test_uncertain_failures_reap_tree_and_never_retry_or_invent_counts(tmp_path, monkeypatch, fault):
    if fault == 'owner':
        instrument(tmp_path, monkeypatch, lambda s: s.replace('ready = self._read_message()',
            "self._supervisor.processes['lab'].kill()\n                ready = self._read_message()"), 'owned_lab')
    if fault == 'pins':
        instrument(tmp_path, monkeypatch, lambda s: s.replace('self._lab_namespaces = observed',
            "os.close(self._namespace_fds[0])\n                self._lab_namespaces = observed"), 'owned_lab')
    if fault == 'admission':
        instrument(tmp_path, monkeypatch, lambda s: s.replace('return value\n',
            "if value.get('sequence') == 2:\n            raise TimeoutError('OWNED-LOST-REDEMPTION')\n        return value\n"), 'admission_isolation')
    launcher, policy = service()
    seen, replies = set(), []
    original = launcher._reply
    def reply():
        seen.update(descendants(launcher._process.pid))
        value = original()
        replies.append(value)
        if fault == 'completion' and len(replies) == 2:
            assert value['result']['owned_lab']['connection_count'] == 1
            seen.update(descendants(launcher._process.pid))
            raise TimeoutError('OWNED-LOST-COMPLETION')
        return value
    monkeypatch.setattr(launcher, '_reply', reply)
    with launcher:
        with pytest.raises(IsolationUnavailable):
            launcher.run(parse_action(discovery_action('a', 1)), policy, control=ExecutionControl(time.monotonic()+20))
        assert launcher._process.poll() is not None
        assert launcher.close()['connection_count'] == launcher.close()['request_count'] == 0
        with pytest.raises(IsolationUnavailable):
            launcher.run(parse_action(discovery_action('a', 1)), policy, control=ExecutionControl(time.monotonic()+20))
    assert_reaped(seen)


@pytest.mark.parametrize('stop', ['cancel', 'deadline', 'concurrent'])
def test_stop_reaps_owner_active_executor_and_admission(tmp_path, monkeypatch, stop):
    instrument(tmp_path, monkeypatch, lambda s: s.replace('    result = operation(',
        "    __import__('time').sleep(30)\n    result = operation("), 'owned_lab_executor')
    launcher, policy = service()
    cancelled = threading.Event()
    control = ExecutionControl(time.monotonic()+(3 if stop == 'deadline' else 20), cancelled)
    observed, executor_seen = set(), False
    with ThreadPoolExecutor(max_workers=1) as pool, launcher:
        pending = pool.submit(launcher.run, parse_action(discovery_action('a', 1)), policy, control=control)
        expiry = time.monotonic()+5
        while time.monotonic() < expiry and not pending.done():
            if hasattr(launcher, '_process'):
                observed.update(descendants(launcher._process.pid))
            for pid in observed:
                try:
                    executor_seen |= b'/app/owned_lab_executor.py' in Path(f'/proc/{pid}/cmdline').read_bytes()
                except FileNotFoundError:
                    pass
            if executor_seen:
                break
            time.sleep(0.01)
        assert executor_seen and not pending.done()
        if stop == 'cancel':
            cancelled.set()
        if stop == 'concurrent':
            with pytest.raises(IsolationUnavailable, match='already running'):
                launcher.run(parse_action(discovery_action('a', 1)), policy, control=control)
        with pytest.raises(IsolationUnavailable if stop == 'concurrent' else ExecutionStopped):
            pending.result(timeout=5)
        assert launcher._closed and launcher.close()['connection_count'] == 0
    assert_reaped(observed)


def test_owned_launcher_cannot_see_host_or_authority_files(tmp_path, monkeypatch):
    secret = tmp_path/'owned-canary'
    secret.write_text('OWNED-CANARY')
    monkeypatch.setenv('OWNED_LAUNCHER_CANARY', 'OWNED-ENV')
    instrument(tmp_path, monkeypatch, lambda s: s.replace('checks = boundary(host)',
        "checks = boundary(host)\n"
        f"        assert not os.path.exists({str(secret)!r})\n"
        "        assert 'OWNED_LAUNCHER_CANARY' not in os.environ\n"
        "        for name in ('controller', 'approvals', 'audit', 'evidence', 'session'):\n"
        "            assert not os.path.exists('/app/recon_cockpit/secure_agent/'+name+'.py')\n"
        "        assert not os.path.exists('/bin/sh') and not os.path.exists('/usr/bin/ldd')"))
    launcher, policy = service()
    with launcher:
        assert launcher.run(parse_action(discovery_action('a', 1)), policy,
                            control=ExecutionControl(time.monotonic()+20))['status'] == 'succeeded'


@pytest.mark.parametrize('execute', [False, True])
def test_owned_dry_or_noninteractive_cli_never_starts_launcher(tmp_path, monkeypatch, capsys, execute):
    from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: False)
    monkeypatch.setattr(cli.sys.stdout, 'isatty', lambda: False)
    monkeypatch.setattr(LinuxFixtureLauncher, '_start', lambda *_: pytest.fail('launcher started'))
    monkeypatch.setattr(OwnedLab, 'start', lambda *_: pytest.fail('host lab started'))
    status = cli.main(['--workflow-assessment', 'a', '--owned-lab', '--isolated-launcher',
        '--isolated-audit', '--isolated-approvals', '--isolated-launch-admission',
        '--policy', 'examples/secure-agent-discovery-policy.json', '--audit', str(tmp_path/'events.jsonl'),
        '--assessment-dir', str(tmp_path/'evidence'), '--execute' if execute else '--dry-run'])
    assert status == (2 if execute else 0)
    output = json.loads(capsys.readouterr().out)
    assert output['live_calls_enabled'] is False and output['workflow_card']['version'] == '2'
    assert output['owned_lab']['closure']['connection_count'] == 0


def test_owned_host_cache_reset_cannot_replenish_worker_budget():
    launcher, policy = service(max_steps=1)
    control = ExecutionControl(time.monotonic()+20)
    with launcher:
        assert launcher.run(parse_action(discovery_action('a', 1)), policy, control=control)['status'] == 'succeeded'
        launcher._sequence = 0
        launcher._snapshot = {'executions_reserved': 0, 'output_bytes_reserved': 0}
        launcher._config['limits']['max_steps'] = 16
        with pytest.raises(IsolationUnavailable):
            launcher.run(parse_action(discovery_action('a', 1)), policy, control=control)
        assert launcher.close()['connection_count'] == 1


@pytest.mark.parametrize('failure', ['denied', 'audit'])
def test_owned_approval_or_audit_failure_never_starts_lab(tmp_path, terminal, monkeypatch, failure):
    from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
    from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
    from recon_cockpit.secure_agent.audit import AuditUnavailable
    from recon_cockpit.secure_agent.controller import Controller
    launcher, policy = service()
    action = parse_action(discovery_action('a', 1))
    control = ExecutionControl(time.monotonic()+20)
    with launcher, LinuxApprovalService(policy, launcher._config['session_id']) as approvals, LinuxAuditSink(tmp_path/'events.jsonl') as audit:
        original = audit.emit
        def emit(event):
            original(event)
            if failure == 'audit' and event['event_type'] == 'execution_started':
                raise AuditUnavailable('OWNED-LOST-ACK')
        monkeypatch.setattr(audit, 'emit', emit)
        controller = Controller(policy, audit, launcher, session_id=launcher._config['session_id'], approvals=approvals)
        grant, _ = scripted_review(approvals, action, policy, terminal, control, b'' if failure == 'denied' else None)
        if failure == 'audit':
            with pytest.raises(AuditUnavailable):
                controller.submit(action.to_dict(), execute=True, interactive=True, approval_reference=grant, execution_control=control)
        else:
            assert controller.submit(action.to_dict(), execute=True, interactive=True, approval_reference=grant, execution_control=control)['execution_status'] == 'blocked'
        assert not hasattr(launcher, '_process') and launcher.close()['connection_count'] == 0
