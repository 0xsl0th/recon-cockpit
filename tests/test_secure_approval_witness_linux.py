"""Owned scripted PTYs verify direct consent mechanics, not operator acceptance."""

from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
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

from recon_cockpit.secure_agent import cli, approval_protocol, audit_protocol, approval_witness
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.approvals import ApprovalUnavailable, ApprovalStore
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.authorized_execution import AuthorizedFixtureBackend
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.planner import proposal
from recon_cockpit.secure_agent.session import SessionLimits
from scripts.secure_agent_control_plane_demo import demo_policy
from test_secure_audit_witness import intent
from test_secure_audit_witness_linux import assert_no_host_fd
from test_secure_approval_linux import terminal, scripted_review, instrument_worker
from test_secure_fixture_launcher_linux import instrument, descendants
from test_secure_launch_admission_linux import run_workflow

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_lab():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for direct consent verification')
    assert sys.platform == 'linux' and os.geteuid() != 0


@contextmanager
def boundary(tmp_path, policy=None):
    policy, session = policy or demo_policy(approval=True), str(uuid4())
    with LinuxAuditSink(tmp_path/'events.jsonl', launch_witness=True) as audit, \
            LinuxApprovalService(policy, session, launch_witness=True) as approvals:
        with LinuxFixtureLauncher(AuthorizedFixtureBackend(policy, session, SessionLimits(), execute=True),
                                  audit=audit, approvals=approvals) as launcher:
            yield audit, approvals, launcher, policy, session


def test_actual_consumed_grant_direct_channel_and_exclusive_custody(tmp_path, monkeypatch, terminal):
    instrument(tmp_path, monkeypatch, lambda s: s.replace('def main() -> int:',
        "def main() -> int:\n"
        "    assert not os.path.exists('/app/recon_cockpit/secure_agent/approval_witness.py')\n"
        "    for name in os.listdir('/proc/self/fd'):\n"
        "        try:\n"
        "            info = os.fstat(int(name))\n"
        "        except OSError:\n"
        "            continue\n"
        "        assert not stat.S_ISSOCK(info.st_mode)"), 'executor_worker')
    with boundary(tmp_path) as (audit, approvals, launcher, policy, session):
        control = ExecutionControl(time.monotonic()+20)
        action = parse_action(proposal())
        source = launcher._approval_source
        writer = os.fstat(approvals._witness_writer.fileno())
        with pytest.raises(OSError) as exc:
            launcher._approval_reader.send(b'forged')
        assert exc.value.errno == errno.EPIPE
        with pytest.raises(ApprovalUnavailable):
            approvals.take_launch_witness()
        reference, _ = scripted_review(approvals, action, policy, terminal, control)
        assert approvals._witness_writer is None
        assert_no_host_fd((writer.st_dev, writer.st_ino))
        controller = Controller(policy, audit, launcher, approvals, session_id=session)
        result = controller.submit(action.to_dict(), execute=True, interactive=True,
                                   approval_reference=reference, execution_control=control)
        assert result['execution_status'] == 'succeeded'
        assert launcher.snapshot['executions_reserved'] == 1
        assert launcher._approval_reader is None
        assert_no_host_fd((source['device'], source['inode']))
        assert approvals.consume(reference, action, policy) == 'approval_unknown_or_replayed'


@pytest.mark.parametrize('backend', ['--fixture', '--owned-lab'])
@pytest.mark.parametrize('case,outcome', [('a', 'validated'), ('b', 'not_demonstrated'), ('c', 'inconclusive'),
                                        ('d', 'inconclusive'), ('e', 'inconclusive'), ('f', 'inconclusive')])
def test_all_workflow_outcomes_with_both_direct_gates(tmp_path, monkeypatch, capsys, terminal, backend, case, outcome):
    original = cli.main
    monkeypatch.setattr(cli, 'main', lambda argv: original([*argv, '--isolated-launcher',
                        '--require-launch-audit', '--require-launch-approval']))
    run_workflow(tmp_path, monkeypatch, capsys, terminal, case, outcome, backend)
    files = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (tmp_path/'evidence').rglob('*') if p.is_file()}
    assert original(['--inspect-assessment', str(tmp_path/'evidence')]) == 0
    assert files == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in files}
    assert json.loads(capsys.readouterr().out)['integrity_issues'] == []


def forbid_admission(tmp_path, monkeypatch):
    instrument(tmp_path, monkeypatch, lambda s: s.replace('granted = gate.admit(',
        "os.write(2, b'UNEXPECTED-ADMISSION')\n                granted = gate.admit("))


def assert_refused(launcher, action, policy, control):
    with pytest.raises((IsolationUnavailable, ExecutionStopped)):
        launcher.run(action, policy, control=control)
    assert launcher._closed and launcher._process.poll() is not None
    assert b'UNEXPECTED' not in bytes(launcher._supervisor.buffers['worker_err'])
    assert launcher.snapshot['executions_reserved'] == 0
    with pytest.raises(IsolationUnavailable):
        launcher.run(action, policy, control=ExecutionControl(time.monotonic()+20))


@pytest.mark.parametrize('fault', ['no_review', 'forged_bootstrap_sender', 'review_only', 'denied', 'forged_consume_reply'])
def test_durable_host_claim_is_not_consent(tmp_path, monkeypatch, terminal, fault):
    forbid_admission(tmp_path, monkeypatch)
    with boundary(tmp_path) as (audit, approvals, launcher, policy, session):
        action = parse_action(proposal())
        control = ExecutionControl(time.monotonic()+4)
        if fault == 'forged_bootstrap_sender':
            # Bootstrap still has its pending sender before first review. It
            # must surrender that capability before any requiring launch.
            grant = ApprovalStore().issue(action, policy)
            proof = approval_witness.witness({'broker_id': approvals._identity,
                'session_id': session, 'policy': policy.to_dict(), 'deadline': control.deadline},
                action, grant, 1, 2, time.monotonic())
            approvals._witness_writer.send(approval_protocol.encode(proof))
        elif fault != 'no_review':
            reference, _ = scripted_review(approvals, action, policy, terminal, control,
                                          b'' if fault == 'denied' else None)
        if fault == 'forged_consume_reply':
            sent = []
            monkeypatch.setattr(approvals, '_send', lambda raw: sent.append(approval_protocol.decode(raw)))
            monkeypatch.setattr(approvals, '_reply', lambda: approval_protocol.receipt(sent[-1], None))
            controller = Controller(policy, audit, launcher, approvals, session_id=session)
            result = controller.submit(action.to_dict(), execute=True, interactive=True,
                approval_reference=reference, execution_control=control)
            assert result['execution_status'] in {'blocked', 'timeout'}
            assert launcher._closed and launcher.snapshot['executions_reserved'] == 0
            assert b'UNEXPECTED' not in bytes(launcher._supervisor.buffers['worker_err'])
        else:
            event = intent(action, policy, session)
            event['approval_reference'] = 'a'*48  # A producer can assert arbitrary consent.
            audit.emit(event)
            assert_refused(launcher, action, policy, control)
            assert approvals._witness_writer is None


@pytest.mark.parametrize('fault', ['broker', 'session', 'action', 'policy', 'stale', 'sequence',
                                  'consume_sequence', 'extra', 'producer_exit', 'expired_grant'])
def test_changed_replayed_expired_or_lost_consent_never_admits(tmp_path, monkeypatch, terminal, fault):
    forbid_admission(tmp_path, monkeypatch)
    changes = {'broker': "proof['broker_id'] = '00000000-0000-0000-0000-000000000000'",
               'session': "proof['session_id'] = '00000000-0000-0000-0000-000000000000'",
               'action': "proof['action_digest'] = 'f'*64", 'policy': "proof['policy_digest'] = 'f'*64",
               'stale': "proof['issued_at'] -= 6", 'sequence': "proof['sequence'] = 0",
               'consume_sequence': "proof['consume_sequence'] = 0"}
    if fault in changes:
        instrument_worker(tmp_path, monkeypatch, lambda s: s.replace('encoded = protocol.encode(proof)',
                          changes[fault]+'\n                    encoded = protocol.encode(proof)'))
    policy = replace(demo_policy(approval=True), approval_ttl_seconds=1 if fault == 'expired_grant' else 5)
    with boundary(tmp_path, policy) as (audit, approvals, launcher, policy, session):
        action, control = parse_action(proposal()), ExecutionControl(time.monotonic()+20)
        reference, _ = scripted_review(approvals, action, policy, terminal, control)
        assert approvals.consume(reference, action, policy) is None
        if fault == 'extra':
            reference, _ = scripted_review(approvals, action, policy, terminal, control)
            assert approvals.consume(reference, action, policy) is None
        if fault == 'producer_exit':
            approvals._process.kill()
            approvals._process.wait(timeout=3)
        if fault == 'expired_grant':
            time.sleep(1.05)
        audit.emit(intent(action, policy, session))
        assert_refused(launcher, action, policy, control)


@pytest.mark.parametrize('fault', ['missing', 'duplicate', 'substitute', 'swap', 'downgrade'])
def test_launcher_bootstrap_requires_both_exact_channels(tmp_path, monkeypatch, fault):
    forbid_admission(tmp_path, monkeypatch)
    with boundary(tmp_path) as (audit, _, launcher, policy, session):
        action = parse_action(proposal())
        original = launcher._send
        unrelated, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with unrelated, peer:
            def send(raw, *, fd=None, approval_fd=None):
                if approval_fd is not None:
                    if fault == 'missing':
                        return original(raw, fd=fd)
                    if fault == 'duplicate':
                        launcher._channel.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                          array.array('i', [fd, approval_fd, approval_fd]))])
                        return
                    if fault == 'substitute':
                        return original(raw, fd=fd, approval_fd=unrelated.fileno())
                    if fault == 'swap':
                        return original(raw, fd=approval_fd, approval_fd=fd)
                    value = json.loads(raw)
                    del value['approval_witness']
                    raw = audit_protocol.encode(value)
                return original(raw, fd=fd, approval_fd=approval_fd)
            monkeypatch.setattr(launcher, '_send', send)
            audit.emit(intent(action, policy, session))
            assert_refused(launcher, action, policy, ExecutionControl(time.monotonic()+20))


def test_expiry_during_admission_still_prevents_executor_creation(tmp_path, monkeypatch, terminal):
    instrument(tmp_path, monkeypatch, lambda s: s.replace('approval_reader.check_fresh(control)',
        'time.sleep(1.1)\n                    try:\n'
        '                        approval_reader.check_fresh(control)\n'
        '                    except ValueError:\n'
        "                        os.write(2, b'EXPECTED-EXPIRED-AFTER-ADMISSION')\n"
        '                        raise').replace(
        'result = (owned.run(', "os.write(2, b'UNEXPECTED-EXECUTION')\n                result = (owned.run("))
    with boundary(tmp_path, replace(demo_policy(approval=True), approval_ttl_seconds=1)) as (audit, approvals, launcher, policy, session):
        action, control = parse_action(proposal()), ExecutionControl(time.monotonic()+20)
        reference, _ = scripted_review(approvals, action, policy, terminal, control)
        assert approvals.consume(reference, action, policy) is None
        audit.emit(intent(action, policy, session))
        assert_refused(launcher, action, policy, control)
        assert b'EXPECTED-EXPIRED-AFTER-ADMISSION' in bytes(launcher._supervisor.buffers['worker_err'])


@pytest.mark.parametrize('fault', ['missing', 'substitute', 'duplicate', 'downgrade'])
def test_approval_worker_bootstrap_cannot_change_sending_endpoint(tmp_path, monkeypatch, terminal, fault):
    with boundary(tmp_path) as (_, approvals, _, policy, _):
        original = approvals._send
        unrelated, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with unrelated, peer:
            def send(raw, *, fd=None, witness_fd=None):
                if witness_fd is not None:
                    if fault == 'missing':
                        return original(raw, fd=fd)
                    if fault == 'substitute':
                        return original(raw, fd=fd, witness_fd=unrelated.fileno())
                    if fault == 'duplicate':
                        approvals._channel.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                            array.array('i', [fd, witness_fd, witness_fd]))])
                        return
                    value = json.loads(raw)
                    del value['witness']
                    raw = approval_protocol.encode(value)
                return original(raw, fd=fd, witness_fd=witness_fd)
            monkeypatch.setattr(approvals, '_send', send)
            with pytest.raises(ApprovalUnavailable):
                approvals.review(parse_action(proposal()), policy, control=ExecutionControl(time.monotonic()+20))
            assert approvals._closed and approvals._process.poll() is not None
            assert approvals._witness_writer is None


def test_lost_consumption_reply_stops_producer_and_cannot_launch(tmp_path, monkeypatch, terminal):
    forbid_admission(tmp_path, monkeypatch)
    with boundary(tmp_path) as (audit, approvals, launcher, policy, session):
        action, control = parse_action(proposal()), ExecutionControl(time.monotonic()+20)
        reference, _ = scripted_review(approvals, action, policy, terminal, control)
        original = approvals._reply
        def reply():
            original()
            raise TimeoutError('OWNED-LOST-CONSUMPTION-ACK')
        monkeypatch.setattr(approvals, '_reply', reply)
        with pytest.raises(ApprovalUnavailable):
            approvals.consume(reference, action, policy)
        assert approvals._closed and approvals._process.poll() is not None
        audit.emit(intent(action, policy, session))
        assert_refused(launcher, action, policy, control)


def test_consumed_proof_cannot_authorize_a_second_launch(tmp_path, terminal):
    with boundary(tmp_path) as (audit, approvals, launcher, policy, session):
        action, control = parse_action(proposal()), ExecutionControl(time.monotonic()+20)
        reference, _ = scripted_review(approvals, action, policy, terminal, control)
        assert approvals.consume(reference, action, policy) is None
        audit.emit(intent(action, policy, session))
        assert launcher.run(action, policy, control=control)['status'] == 'succeeded'
        assert approvals.consume(reference, action, policy) == 'approval_unknown_or_replayed'
        audit.emit(intent(action, policy, session))
        with pytest.raises(IsolationUnavailable):
            launcher.run(action, policy, control=control)
        assert launcher._closed and launcher._process.poll() is not None
        assert launcher.snapshot['executions_reserved'] == 1


def test_allow_policy_needs_no_terminal_but_still_requires_durable_intent(tmp_path, monkeypatch):
    from recon_cockpit.secure_agent import approval_isolation
    monkeypatch.setattr(approval_isolation, '_open_terminal', lambda: pytest.fail('unexpected terminal'))
    with boundary(tmp_path, demo_policy()) as (audit, approvals, launcher, policy, session):
        action = parse_action(proposal())
        audit.emit(intent(action, policy, session))
        assert launcher.run(action, policy, control=ExecutionControl(time.monotonic()+20))['status'] == 'succeeded'
        assert approvals.boundary_checks is None and not hasattr(approvals, '_process')


def test_cancellation_waiting_for_consent_reaps_launcher(tmp_path, terminal):
    with boundary(tmp_path) as (audit, approvals, launcher, policy, session):
        action = parse_action(proposal())
        cancelled = threading.Event()
        control = ExecutionControl(time.monotonic()+20, cancelled)
        scripted_review(approvals, action, policy, terminal, control, b'')
        audit.emit(intent(action, policy, session))
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(launcher.run, action, policy, control=control)
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
    assert approvals._process.poll() is not None


@pytest.mark.parametrize('execute', [False, True])
def test_dry_or_noninteractive_cli_starts_no_launcher_or_approval(tmp_path, monkeypatch, capsys, execute):
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: False)
    monkeypatch.setattr(cli.sys.stdout, 'isatty', lambda: False)
    monkeypatch.setattr(LinuxFixtureLauncher, '_start', lambda *_: pytest.fail('launcher started'))
    monkeypatch.setattr(LinuxApprovalService, '_start', lambda *_: pytest.fail('approval started'))
    status = cli.main(['--workflow-assessment', 'a', '--owned-lab', '--isolated-launcher',
        '--require-launch-audit', '--require-launch-approval', '--isolated-audit',
        '--isolated-approvals', '--isolated-launch-admission', '--policy', 'examples/secure-agent-discovery-policy.json',
        '--audit', str(tmp_path/'events.jsonl'), '--assessment-dir', str(tmp_path/'evidence'),
        '--execute' if execute else '--dry-run'])
    assert status == (2 if execute else 0)
    assert json.loads(capsys.readouterr().out)['owned_lab']['closure']['connection_count'] == 0
