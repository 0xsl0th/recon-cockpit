"""Actual direct audit-to-launcher witnesses in disconnected owned namespaces."""

from concurrent.futures import ThreadPoolExecutor
import array
import errno
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import audit_protocol, audit_worker, cli
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.authorized_execution import AuthorizedFixtureBackend
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.planner import proposal
from recon_cockpit.secure_agent.session import SessionLimits
from scripts.secure_agent_control_plane_demo import demo_policy
from test_secure_audit_witness import intent
from test_secure_approval_linux import terminal, scripted_review
from test_secure_launch_admission_linux import run_workflow
from test_secure_fixture_launcher_linux import instrument, descendants

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_lab():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for direct audit-witness verification')
    assert sys.platform == 'linux' and os.geteuid() != 0


def launcher_for(audit):
    policy, session = demo_policy(), str(uuid4())
    launcher = LinuxFixtureLauncher(AuthorizedFixtureBackend(policy, session, SessionLimits(), execute=True), audit=audit)
    return launcher, policy, session


def instrument_writer(tmp_path, monkeypatch, transform):
    candidate = tmp_path/'audit-worker.py'
    candidate.write_text(transform(Path(audit_worker.__file__).read_text()))
    original = LinuxAuditSink._command
    def command(self, *args):
        argv = original(self, *args)
        argv[argv.index('/app/audit_worker.py')-1] = str(candidate)
        return argv
    monkeypatch.setattr(LinuxAuditSink, '_command', command)


def assert_no_host_fd(identity):
    for fd in os.listdir('/proc/self/fd'):
        try:
            info = os.fstat(int(fd))
        except OSError:
            continue
        assert (info.st_dev, info.st_ino) != identity


def test_real_durable_witness_and_exclusive_endpoint_custody(tmp_path, monkeypatch):
    instrument(tmp_path, monkeypatch, lambda s: s.replace('def main() -> int:',
        "def main() -> int:\n"
        "    assert not os.path.exists('/app/recon_cockpit/secure_agent/audit_witness.py')\n"
        "    for name in os.listdir('/proc/self/fd'):\n"
        "        try:\n"
        "            info = os.fstat(int(name))\n"
        "        except OSError:\n"
        "            continue\n"
        "        assert not stat.S_ISSOCK(info.st_mode)"), 'executor_worker')
    captured = []
    original = LinuxAuditSink._send
    def send(self, raw, **kwargs):
        if kwargs.get('witness_fd') is not None:
            info = os.fstat(kwargs['witness_fd'])
            captured.append((info.st_dev, info.st_ino))
        return original(self, raw, **kwargs)
    monkeypatch.setattr(LinuxAuditSink, '_send', send)
    with LinuxAuditSink(tmp_path/'events.jsonl', launch_witness=True) as audit:
        assert len(captured) == 1
        assert_no_host_fd(captured[0])
        launcher, policy, session = launcher_for(audit)
        with launcher:
            with pytest.raises(AuditUnavailable):
                audit.take_launch_witness()
            with pytest.raises(OSError) as exc:
                launcher._witness_reader.send(b'forged')
            assert exc.value.errno == errno.EPIPE
            source = launcher._witness_source
            action = parse_action(proposal())
            event = intent(action, policy, session)
            audit.emit(event)
            assert json.loads((tmp_path/'events.jsonl').read_text())['action_digest'] == action.digest
            assert launcher.run(action, policy, control=ExecutionControl(time.monotonic()+20))['status'] == 'succeeded'
            assert launcher._witness_reader is None
            assert_no_host_fd((source['device'], source['inode']))
            assert_no_host_fd(captured[0])


@pytest.mark.parametrize('fault', ['missing_fd', 'duplicate_fd', 'replaced_fd', 'downgrade'])
def test_bootstrap_cannot_drop_gate_or_replace_channel(tmp_path, monkeypatch, fault):
    with LinuxAuditSink(tmp_path/'events.jsonl', launch_witness=True) as audit:
        launcher, policy, _ = launcher_for(audit)
        unrelated, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with launcher, unrelated, peer:
            original = launcher._send
            def send(raw, *, fd=None):
                if fd is not None:
                    if fault == 'duplicate_fd':
                        launcher._channel.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd, fd]))])
                        return
                    if fault == 'missing_fd':
                        return original(raw)
                    if fault == 'replaced_fd':
                        return original(raw, fd=unrelated.fileno())
                    if fault == 'downgrade':
                        value = json.loads(raw)
                        del value['audit_witness']
                        raw = audit_protocol.encode(value)
                return original(raw, fd=fd)
            monkeypatch.setattr(launcher, '_send', send)
            with pytest.raises(IsolationUnavailable):
                launcher.run(parse_action(proposal()), policy, control=ExecutionControl(time.monotonic()+20))
            assert launcher._closed and launcher._process.poll() is not None and launcher.boundary_checks is None


@pytest.mark.parametrize('fault', ['missing', 'forged_host_ack', 'session', 'action', 'policy', 'backend', 'stale', 'replay', 'extra'])
def test_missing_forged_mismatched_or_replayed_intent_never_admits(tmp_path, monkeypatch, fault):
    instrument(tmp_path, monkeypatch, lambda s: s.replace('granted = gate.admit(',
        "os.write(2, b'UNEXPECTED-ADMISSION')\n                granted = gate.admit("))
    if fault == 'stale':
        instrument_writer(tmp_path, monkeypatch, lambda s: s.replace("proof['issued_at'] = time.monotonic()", "proof['issued_at'] = time.monotonic()-6"))
    if fault == 'replay':
        instrument_writer(tmp_path, monkeypatch, lambda s: s.replace('encoded = protocol.encode(proof)', "proof['sequence'] = 0\n                encoded = protocol.encode(proof)"))
    with LinuxAuditSink(tmp_path/'events.jsonl', launch_witness=True) as audit:
        launcher, policy, session = launcher_for(audit)
        with launcher:
            action = parse_action(proposal())
            event = intent(action, policy, session)
            if fault == 'forged_host_ack':
                # The host thinks the normal audit RPC succeeded; no event was
                # sent to the real writer, so it cannot supply a direct witness.
                monkeypatch.setattr(audit, '_send', lambda *_: None)
                monkeypatch.setattr(audit, '_reply', lambda: audit_protocol.receipt(
                    audit._identity, audit._sequence+1, audit_protocol.event_bytes(event)))
            changes = {'session': ('session_id', str(uuid4())), 'action': ('action_digest', 'f'*64),
                       'policy': ('policy_digest', 'f'*64), 'backend': ('backend', 'forged')}
            if fault in changes:
                key, value = changes[fault]
                event[key] = value
            if fault != 'missing':
                audit.emit(event)
            if fault == 'extra':
                audit.emit(event)
            with pytest.raises((IsolationUnavailable, ExecutionStopped)):
                launcher.run(action, policy, control=ExecutionControl(time.monotonic()+2))
            assert launcher._closed and launcher._process.poll() is not None
            assert b'UNEXPECTED' not in bytes(launcher._supervisor.buffers['worker_err'])
            assert launcher.snapshot['executions_reserved'] == 0
            with pytest.raises(IsolationUnavailable):
                launcher.run(action, policy, control=ExecutionControl(time.monotonic()+20))


@pytest.mark.parametrize('failure', ['fsync', 'lost_ack', 'writer_exit', 'channel_closed'])
def test_audit_failures_cannot_turn_into_launch_permission(tmp_path, monkeypatch, failure):
    instrument(tmp_path, monkeypatch, lambda s: s.replace('granted = gate.admit(',
        "os.write(2, b'UNEXPECTED-ADMISSION')\n                granted = gate.admit("))
    if failure == 'fsync':
        instrument_writer(tmp_path, monkeypatch, lambda s: s.replace('os.fsync(fd)', "raise OSError('OWNED-FSYNC-FAILURE')"))
    with LinuxAuditSink(tmp_path/'events.jsonl', launch_witness=True) as audit:
        launcher, policy, session = launcher_for(audit)
        with launcher:
            action = parse_action(proposal())
            if failure == 'lost_ack':
                original = audit._reply
                def reply():
                    original()
                    raise TimeoutError('OWNED-LOST-ACK')
                monkeypatch.setattr(audit, '_reply', reply)
            if failure == 'channel_closed':
                launcher._witness_reader.close()
            if failure in {'fsync', 'lost_ack', 'channel_closed'}:
                with pytest.raises(AuditUnavailable):
                    audit.emit(intent(action, policy, session))
            else:
                audit._process.kill()
                with pytest.raises(AuditUnavailable):
                    audit.emit(intent(action, policy, session))
            with pytest.raises((IsolationUnavailable, ExecutionStopped)):
                launcher.run(action, policy, control=ExecutionControl(time.monotonic()+2))
            assert launcher._closed and launcher.snapshot['executions_reserved'] == 0
            if launcher._supervisor is not None:
                assert b'UNEXPECTED' not in bytes(launcher._supervisor.buffers['worker_err'])


@pytest.mark.parametrize('backend', ['--fixture', '--owned-lab'])
@pytest.mark.parametrize('case,outcome', [('a', 'validated'), ('b', 'not_demonstrated'), ('c', 'inconclusive'),
                                        ('d', 'inconclusive'), ('e', 'inconclusive'), ('f', 'inconclusive')])
def test_all_workflow_outcomes_with_direct_audit_gate(tmp_path, monkeypatch, capsys, terminal, backend, case, outcome):
    original = cli.main
    monkeypatch.setattr(cli, 'main', lambda argv: original([*argv, '--isolated-launcher', '--require-launch-audit']))
    run_workflow(tmp_path, monkeypatch, capsys, terminal, case, outcome, backend)
    files = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (tmp_path/'evidence').rglob('*') if p.is_file()}
    assert original(['--inspect-assessment', str(tmp_path/'evidence')]) == 0
    assert files == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in files}
    assert json.loads(capsys.readouterr().out)['integrity_issues'] == []


@pytest.mark.parametrize('execute', [False, True])
def test_dry_or_noninteractive_cli_starts_no_launcher(tmp_path, monkeypatch, capsys, execute):
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: False)
    monkeypatch.setattr(cli.sys.stdout, 'isatty', lambda: False)
    monkeypatch.setattr(LinuxFixtureLauncher, '_start', lambda *_: pytest.fail('launcher started'))
    status = cli.main(['--workflow-assessment', 'a', '--owned-lab', '--isolated-launcher', '--require-launch-audit',
        '--isolated-audit', '--isolated-approvals', '--isolated-launch-admission',
        '--policy', 'examples/secure-agent-discovery-policy.json', '--audit', str(tmp_path/'events.jsonl'),
        '--assessment-dir', str(tmp_path/'evidence'), '--execute' if execute else '--dry-run'])
    assert status == (2 if execute else 0)
    assert json.loads(capsys.readouterr().out)['owned_lab']['closure']['connection_count'] == 0


def test_cancellation_waiting_for_witness_reaps_launcher(tmp_path):
    with LinuxAuditSink(tmp_path/'events.jsonl', launch_witness=True) as audit:
        launcher, policy, _ = launcher_for(audit)
        cancelled = threading.Event()
        control = ExecutionControl(time.monotonic()+20, cancelled)
        with ThreadPoolExecutor(max_workers=1) as pool, launcher:
            pending = pool.submit(launcher.run, parse_action(proposal()), policy, control=control)
            expiry = time.monotonic()+5
            while launcher.boundary_checks is None and not pending.done() and time.monotonic() < expiry:
                time.sleep(0.01)
            assert launcher.boundary_checks is not None and not pending.done()
            observed = descendants(launcher._process.pid)
            cancelled.set()
            with pytest.raises(ExecutionStopped):
                pending.result(timeout=5)
            assert launcher._process.poll() is not None
            expiry = time.monotonic()+3
            while any(Path(f'/proc/{pid}').exists() for pid in observed) and time.monotonic() < expiry:
                time.sleep(0.02)
            assert not any(Path(f'/proc/{pid}').exists() for pid in observed)


@pytest.mark.parametrize('failure', ['denied', 'audit_ack'])
def test_grant_denial_or_lost_controller_ack_prevents_start(tmp_path, monkeypatch, terminal, failure):
    from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
    from recon_cockpit.secure_agent.controller import Controller
    policy, session = demo_policy(approval=True), str(uuid4())
    with LinuxAuditSink(tmp_path/'events.jsonl', launch_witness=True) as audit, LinuxApprovalService(policy, session) as approvals:
        with LinuxFixtureLauncher(AuthorizedFixtureBackend(policy, session, SessionLimits(), execute=True), audit=audit) as launcher:
            action = parse_action(proposal())
            control = ExecutionControl(time.monotonic()+20)
            grant, _ = scripted_review(approvals, action, policy, terminal, control, b'' if failure == 'denied' else None)
            original = audit.emit
            def emit(event):
                original(event)
                if failure == 'audit_ack' and event['event_type'] == 'execution_started':
                    raise AuditUnavailable('OWNED-LOST-CONTROLLER-ACK')
            monkeypatch.setattr(audit, 'emit', emit)
            controller = Controller(policy, audit, launcher, approvals, session_id=session)
            if failure == 'audit_ack':
                with pytest.raises(AuditUnavailable):
                    controller.submit(action.to_dict(), execute=True, interactive=True, approval_reference=grant, execution_control=control)
            else:
                assert controller.submit(action.to_dict(), execute=True, interactive=True, approval_reference=grant, execution_control=control)['execution_status'] == 'blocked'
            assert not hasattr(launcher, '_process')
