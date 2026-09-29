"""Owned nested launcher boundaries; no external network/provider execution."""

import array
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import launcher_worker, launcher_protocol as protocol, cli
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.authorized_execution import AuthorizedFixtureBackend
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.coordinator_isolation import LinuxCoordinator
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.planner import proposal
from recon_cockpit.secure_agent.session import SessionLimits
from scripts.secure_agent_control_plane_demo import demo_policy
from test_secure_approval_linux import terminal, scripted_review
from test_secure_launch_admission_linux import run_workflow

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_lab():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for actual launcher isolation')
    assert sys.platform == 'linux' and os.geteuid() != 0


def service(**limits):
    return LinuxFixtureLauncher(AuthorizedFixtureBackend(demo_policy(), str(uuid4()), SessionLimits(**limits), execute=True))


def instrument(tmp_path, monkeypatch, transform, name='launcher_worker'):
    candidate = tmp_path/(name+'.py')
    candidate.write_text(transform(Path(launcher_worker.__file__).with_name(name+'.py').read_text()))
    original = LinuxFixtureLauncher._command
    def command(self, *args):
        argv = original(self, *args)
        destination = '/app/recon_cockpit/secure_agent/'+name+'.py'
        argv[argv.index(destination)-1] = str(candidate)
        return argv
    monkeypatch.setattr(LinuxFixtureLauncher, '_command', command)


def test_actual_launch_and_independent_worker_state_survive_host_counter_reset(monkeypatch):
    monkeypatch.setattr(AuthorizedFixtureBackend, 'run', lambda *_a, **_k: pytest.fail('host executor called'))
    control = ExecutionControl(time.monotonic()+20)
    with service(max_steps=1) as launcher:
        result = launcher.run(parse_action(proposal()), demo_policy(), control=control)
        assert result['status'] == 'succeeded' and result['results'][0]['http_status'] == 200
        assert launcher.boundary_checks == dict.fromkeys(protocol.CHECKS, True)
        assert dict(launcher.snapshot) == {'executions_reserved': 1, 'output_bytes_reserved': 1024}
        launcher._sequence = 0
        launcher._snapshot = {'executions_reserved': 0, 'output_bytes_reserved': 0}
        with pytest.raises(IsolationUnavailable):
            launcher.run(parse_action(proposal()), demo_policy(), control=control)
        assert launcher._closed and launcher._process.poll() is not None


def test_worker_output_budget_cannot_be_refunded_by_host_cache_or_config_changes():
    control = ExecutionControl(time.monotonic()+20)
    with service(max_output_bytes=1024) as launcher:
        assert launcher.run(parse_action(proposal()), demo_policy(), control=control)['status'] == 'succeeded'
        launcher._snapshot['output_bytes_reserved'] = 0
        launcher._config['limits']['max_output_bytes'] = 1048576
        with pytest.raises(IsolationUnavailable):
            launcher.run(parse_action(proposal()), demo_policy(), control=control)
        assert launcher._closed and launcher._process.poll() is not None


def test_launcher_cannot_see_host_files_environment_descriptors_or_listener(tmp_path, monkeypatch):
    canary = tmp_path/'host-secret'
    canary.write_text('OWNED-CANARY')
    monkeypatch.setenv('RECON_LAUNCHER_CANARY', 'OWNED-ENV')
    fd = os.open(canary, os.O_RDONLY)
    os.set_inheritable(fd, True)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        instrument(tmp_path, monkeypatch, lambda source: source.replace(
            'checks = boundary(host)', 'checks = boundary(host)\n'
            "        assert 'RECON_LAUNCHER_CANARY' not in os.environ\n"
            f"        assert not os.path.exists({str(canary)!r})\n"
            "        assert not os.path.exists('/bin/sh') and not os.path.exists('/usr/bin/ldd')\n"
            "        assert not os.path.exists('/app/recon_cockpit/secure_agent/approvals.py')\n"
            "        witness = socket.socket()\n"
            f"        assert witness.connect_ex(('127.0.0.1', {port})) != 0\n"
            "        witness.close()"))
        try:
            with service() as launcher:
                assert launcher.run(parse_action(proposal()), demo_policy(), control=ExecutionControl(time.monotonic()+20))['status'] == 'succeeded'
        finally:
            os.close(fd)


@pytest.mark.parametrize('malice', ['sequence', 'session', 'service', 'permit', 'approved', 'audit', 'command',
    'reset', 'budget', 'deadline', 'policy', 'action', 'duplicate', 'oversized', 'extra_fd'])
def test_forged_requests_kill_worker_without_launch(tmp_path, monkeypatch, malice):
    instrument(tmp_path, monkeypatch, lambda source: source.replace(
        'control.check()\n    nonce', "os.write(2, b'OWNED-UNEXPECTED-LAUNCH')\n    control.check()\n    nonce"))
    with service() as launcher:
        control = ExecutionControl(time.monotonic()+20)
        launcher._start(control)
        config = launcher._config
        value = {'version': '1', 'service_id': config['service_id'], 'session_id': config['session_id'],
            'sequence': 1, 'operation': 'execute', 'action': proposal(), 'policy_digest': demo_policy().digest}
        changes = {'sequence': ('sequence', 2), 'session': ('session_id', str(uuid4())),
            'service': ('service_id', str(uuid4())), 'permit': ('permit', 'f'*64), 'approved': ('approved', True),
            'audit': ('audit_acknowledged', True), 'command': ('command', 'id'), 'reset': ('operation', 'reset'),
            'budget': ('output_reserved_before', 0), 'deadline': ('deadline', time.monotonic()+600),
            'policy': ('policy_digest', 'f'*64), 'action': ('action', {**proposal(), 'target': '192.0.2.1'})}
        if malice in changes:
            key, item = changes[malice]
            value[key] = item
        raw = json.dumps(value).encode()
        if malice == 'duplicate':
            raw = b'{"version":"1",'+raw[1:]
        if malice == 'oversized':
            raw = b'x'*32769
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [1]))] if malice == 'extra_fd' else []
        launcher._channel.sendmsg([raw], ancillary)
        assert launcher._process.wait(timeout=5) == 78
        assert b'OWNED-UNEXPECTED' not in (launcher._process.stderr.read() or b'')
        with pytest.raises(IsolationUnavailable):
            launcher.run(parse_action(proposal()), demo_policy(), control=control)
        assert launcher._closed


@pytest.mark.parametrize('failure', ['ready', 'reply', 'flood', 'lost_admission', 'dead_admission', 'lost_execution', 'init'])
def test_faults_poison_client_and_cannot_replay(tmp_path, monkeypatch, failure):
    if failure in {'ready', 'reply', 'flood'}:
        old, new = {
            'ready': ("'ready': True, 'bootstrap_digest'", "'ready': False, 'bootstrap_digest'"),
            'reply': ('protocol.receipt(value, result, gate.snapshot)', "{**protocol.receipt(value, result, gate.snapshot), 'sequence': 99}"),
            'flood': ('sequence = 1', "print('x' * (protocol.MAX_REPLY+1), flush=True)\n            sequence = 1")}[failure]
        instrument(tmp_path, monkeypatch, lambda source: source.replace(old, new))
    if failure in {'lost_admission', 'dead_admission'}:
        instrument(tmp_path, monkeypatch, lambda source: source.replace(
            'control.check()\n    nonce', "os.write(2, b'OWNED-UNEXPECTED-LAUNCH')\n    control.check()\n    nonce"))
        if failure == 'lost_admission':
            instrument(tmp_path, monkeypatch, lambda source: source.replace('return value\n',
                "if value.get('sequence') == 2:\n            raise TimeoutError('OWNED-LOST-REDEMPTION')\n        return value\n"), 'admission_isolation')
        else:
            instrument(tmp_path, monkeypatch, lambda source: source.replace('seal()\n', 'seal()\n        os._exit(78)\n'), 'admission_worker')
    with service() as launcher:
        replies = []
        original = launcher._reply
        def reply():
            value = original()
            replies.append(value)
            if failure == 'lost_execution' and len(replies) == 2:
                assert value['result']['status'] == 'succeeded'  # Completion is uncertain, never safe to retry.
                raise TimeoutError('OWNED-LOST-COMPLETION')
            return value
        monkeypatch.setattr(launcher, '_reply', reply)
        if failure == 'init':
            original_send = launcher._send
            def send(raw):
                value = json.loads(raw)
                if 'configuration' in value:
                    value['configuration']['limits']['max_steps'] = 16
                original_send(json.dumps(value).encode())
            monkeypatch.setattr(launcher, '_send', send)
        with pytest.raises(IsolationUnavailable):
            launcher.run(parse_action(proposal()), demo_policy(), control=ExecutionControl(time.monotonic()+20))
        assert launcher._closed and launcher._process.poll() is not None
        assert b'OWNED-UNEXPECTED' not in bytes(launcher._supervisor.buffers['worker_err'])
        with pytest.raises(IsolationUnavailable):
            launcher.run(parse_action(proposal()), demo_policy(), control=ExecutionControl(time.monotonic()+20))


def descendants(pid):
    found = set()
    try:
        children = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
    except FileNotFoundError:
        return found
    for child in children:
        found.add(int(child))
        found.update(descendants(int(child)))
    return found


@pytest.mark.parametrize('stop', ['cancel', 'deadline', 'concurrent'])
def test_stop_reaps_active_executor_and_nested_admission(tmp_path, monkeypatch, stop):
    instrument(tmp_path, monkeypatch, lambda source: source.replace(
        'result = (worker.execute_tcp_connect', 'time.sleep(30)\n        result = (worker.execute_tcp_connect'), 'executor_worker')
    cancelled = threading.Event()
    control = ExecutionControl(time.monotonic()+(2 if stop == 'deadline' else 20), cancelled)
    with ThreadPoolExecutor(max_workers=1) as pool, service() as launcher:
        pending = pool.submit(launcher.run, parse_action(proposal()), demo_policy(), control=control)
        observed = set()
        deadline = time.monotonic()+5
        while time.monotonic() < deadline and not pending.done():
            if hasattr(launcher, '_process'):
                observed.update(descendants(launcher._process.pid))
            if any(Path(f'/proc/{pid}/cmdline').exists() and b'/app/executor_worker.py' in Path(f'/proc/{pid}/cmdline').read_bytes()
                   for pid in observed):
                break
            time.sleep(0.01)
        assert observed and not pending.done()
        if stop == 'cancel':
            cancelled.set()
        if stop == 'concurrent':
            with pytest.raises(IsolationUnavailable, match='already running'):
                launcher.run(parse_action(proposal()), demo_policy(), control=control)
        with pytest.raises(IsolationUnavailable if stop == 'concurrent' else ExecutionStopped):
            pending.result(timeout=5)
        assert launcher._closed and launcher._process.poll() is not None
        expiry = time.monotonic()+3
        while any(Path(f'/proc/{pid}').exists() for pid in observed) and time.monotonic() < expiry:
            time.sleep(0.02)
        assert not any(Path(f'/proc/{pid}').exists() for pid in observed)


def test_authority_consumes_grants_and_persists_intent_before_remote_launch(tmp_path, terminal, monkeypatch):
    policy, session_id, limits = demo_policy(approval=True), str(uuid4()), SessionLimits()
    path = tmp_path/'events.jsonl'
    backend = AuthorizedFixtureBackend(policy, session_id, limits, execute=True)
    monkeypatch.setattr(backend, 'run', lambda *_a, **_k: pytest.fail('host launch'))
    launches = []
    with LinuxFixtureLauncher(backend) as launcher, LinuxApprovalService(policy, session_id) as approvals, LinuxAuditSink(path) as audit:
        original = launcher.run
        def run(chosen, supplied_policy, *, control):
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            assert rows[-1]['event_type'] == 'execution_started' and rows[-2]['event_type'] == 'approval_consumed'
            launches.append(chosen.digest)
            return original(chosen, supplied_policy, control=control)
        monkeypatch.setattr(launcher, 'run', run)
        runner = AuthoritySession(policy, audit, launcher, LinuxCoordinator(), limits, session_id=session_id, approvals=approvals)
        def review(controller, raw, *, control):
            return scripted_review(approvals, parse_action(raw), policy, terminal, control)[0]
        summary = runner.run(execute=True, interactive=True, approval=review)
        assert summary['actions_succeeded'] == len(launches) == 3
        assert launcher.snapshot['executions_reserved'] == 3
    assert launcher._process.poll() is not None


@pytest.mark.parametrize('case,outcome', [('a', 'validated'), ('b', 'not_demonstrated'), ('c', 'inconclusive'),
                                        ('d', 'inconclusive'), ('e', 'inconclusive'), ('f', 'inconclusive')])
def test_all_workflow_outcomes_with_confined_launcher(tmp_path, monkeypatch, capsys, terminal, case, outcome):
    original = cli.main
    monkeypatch.setattr(cli, 'main', lambda argv: original([*argv, '--isolated-launcher']))
    monkeypatch.setattr(AuthorizedFixtureBackend, 'run', lambda *_a, **_k: pytest.fail('host executor called'))
    run_workflow(tmp_path, monkeypatch, capsys, terminal, case, outcome, '--fixture')


@pytest.mark.parametrize('failure', ['denied', 'audit'])
def test_approval_or_audit_failure_prevents_launcher_start(tmp_path, terminal, monkeypatch, failure):
    from recon_cockpit.secure_agent.audit import AuditUnavailable
    policy, session_id, limits = demo_policy(approval=True), str(uuid4()), SessionLimits()
    with LinuxFixtureLauncher(AuthorizedFixtureBackend(policy, session_id, limits, execute=True)) as launcher, \
            LinuxApprovalService(policy, session_id) as approvals, LinuxAuditSink(tmp_path/'events.jsonl') as audit:
        original = audit.emit
        def emit(event):
            original(event)
            if failure == 'audit' and event['event_type'] == 'execution_started':
                raise AuditUnavailable('OWNED-LOST-ACK')
        monkeypatch.setattr(audit, 'emit', emit)
        runner = AuthoritySession(policy, audit, launcher, LinuxCoordinator(), limits, session_id=session_id, approvals=approvals)
        def review(controller, raw, *, control):
            return scripted_review(approvals, parse_action(raw), policy, terminal, control, b'' if failure == 'denied' else None)[0]
        if failure == 'audit':
            with pytest.raises(AuditUnavailable):
                runner.run(execute=True, interactive=True, approval=review)
        else:
            assert runner.run(execute=True, interactive=True, approval=review)['stop_reason'] == 'action_blocked'
        assert not hasattr(launcher, '_process') and launcher._control is None
