"""Opt-in owned Linux evidence for the confined audit writer and launch gate."""

import array
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import audit_protocol as protocol, audit_worker, cli
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.authorized_execution import AuthorizedFixtureBackend
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.coordinator_isolation import LinuxCoordinator
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.session import SessionLimits
from scripts.secure_agent_control_plane_demo import demo_policy

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_lab():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for real audit isolation')
    assert sys.platform == 'linux' and os.geteuid() != 0


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def proposal():
    return {'schema_version': '1', 'action_id': str(uuid4()), 'tool_id': 'http_probe',
            'target': '127.0.0.1', 'parameters': {'port': 8080, 'method': 'GET', 'path': '/',
            'timeout_seconds': 1, 'max_output_bytes': 1024}, 'rationale': 'owned fixture'}


def test_writer_descriptor_is_exclusive_and_all_children_reaped(tmp_path):
    path = tmp_path / 'events.jsonl'
    sink = LinuxAuditSink(path)
    child = sink._process
    with sink:
        assert sink.boundary_checks == dict.fromkeys(protocol.CHECKS, True)
        identity = path.stat()
        for descriptor in os.listdir('/proc/self/fd'):
            try:
                info = os.fstat(int(descriptor))
            except OSError:
                continue
            assert (info.st_dev, info.st_ino) != (identity.st_dev, identity.st_ino)
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda n: sink.emit({'event_type': 'owned_concurrent', 'number': n}), range(16)))
        assert sink._sequence == 16
    assert child.poll() == 0
    assert sorted(row['number'] for row in records(path)) == list(range(16))
    assert len({row['event_id'] for row in records(path)}) == 16
    with pytest.raises(AuditUnavailable):
        sink.emit({'event_type': 'after_close'})


def test_host_environment_file_and_inheritable_fd_are_absent(tmp_path, monkeypatch):
    canary = tmp_path / 'host-secret'
    canary.write_text('OWNED-HOST-CANARY')
    monkeypatch.setenv('RECON_AUDIT_HOST_CANARY', 'OWNED-ENV-CANARY')
    fd = os.open(canary, os.O_RDONLY)
    os.set_inheritable(fd, True)
    # Test-only fixed worker instrumentation. It is never selectable by CLI.
    source = Path(audit_worker.__file__).read_text()
    source = source.replace("checks = bootstrap._bootstrap(host)",
        "checks = bootstrap._bootstrap(host)\n"
        "        assert 'RECON_AUDIT_HOST_CANARY' not in os.environ\n"
        f"        assert not os.path.exists({str(canary)!r})")
    candidate = tmp_path / 'canary-worker.py'
    candidate.write_text(source)
    original = LinuxAuditSink._command

    def command(self, *args):
        argv = original(self, *args)
        index = argv.index('/app/audit_worker.py')
        argv[index - 1] = str(candidate)
        return argv

    monkeypatch.setattr(LinuxAuditSink, '_command', command)
    try:
        with LinuxAuditSink(tmp_path / 'events.jsonl') as sink:
            sink.emit({'event_type': 'owned_canary'})
    finally:
        os.close(fd)
    assert 'CANARY' not in (tmp_path / 'events.jsonl').read_text()


@pytest.mark.parametrize('change', ['replace', 'chmod', 'link', 'remove', 'child_exit'])
def test_changed_file_or_dead_writer_permanently_stops_appends(tmp_path, change):
    path = tmp_path / 'events.jsonl'
    sink = LinuxAuditSink(path)
    child = sink._process
    sink.emit({'event_type': 'before_change'})
    if change == 'replace':
        path.rename(tmp_path / 'original.jsonl')
        path.touch(mode=0o600)
    elif change == 'chmod':
        path.chmod(0o644)
    elif change == 'link':
        os.link(path, tmp_path / 'alias')
    elif change == 'remove':
        path.unlink()
    else:
        child.kill()
        child.wait(timeout=2)
    with pytest.raises(AuditUnavailable):
        sink.emit({'event_type': 'must_not_append'})
    with pytest.raises(AuditUnavailable):
        sink.emit({'event_type': 'must_not_retry'})
    assert child.poll() is not None
    sink.close()


@pytest.mark.parametrize('malice', ['replay', 'wrong_writer', 'extra_field', 'extra_fd', 'oversized'])
def test_real_worker_rejects_protocol_attacks_without_another_append(tmp_path, malice):
    path = tmp_path / 'events.jsonl'
    sink = LinuxAuditSink(path)
    sink.emit({'event_type': 'first'})
    value = {'version': '1', 'writer_id': sink._identity, 'sequence': 2,
             'event': {'event_type': 'must_not_append'}}
    ancillary = []
    extra_fd = None
    if malice == 'replay':
        value['sequence'] = 1
    elif malice == 'wrong_writer':
        value['writer_id'] = str(uuid4())
    elif malice == 'extra_field':
        value['path'] = '/tmp/forged'
    elif malice == 'extra_fd':
        extra_fd = os.open(path, os.O_RDONLY)
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [extra_fd]))]
    raw = b'x' * (protocol.MAX_PACKET + 1) if malice == 'oversized' else protocol.encode(value)
    try:
        sink._channel.sendmsg([raw], ancillary)
        sink._process.wait(timeout=3)
        with pytest.raises(AuditUnavailable):
            sink.emit({'event_type': 'must_not_resume'})
    finally:
        if extra_fd is not None:
            os.close(extra_fd)
        sink._cleanup()
    assert [row['event_type'] for row in records(path)] == ['first']


@pytest.mark.parametrize('failure', ['fsync', 'silent', 'flood', 'forged_receipt'])
def test_failed_or_unresponsive_real_worker_cannot_ack_intent(tmp_path, monkeypatch, failure):
    source = Path(audit_worker.__file__).read_text()
    if failure == 'fsync':
        source = source.replace('os.fsync(fd)', "raise OSError('owned fsync fault')")
    elif failure == 'silent':
        source = source.replace("append(fd, value['event'])", "time.sleep(30)")
    elif failure == 'flood':
        source = source.replace("append(fd, value['event'])", "print('x' * 1048577, flush=True)")
    else:
        source = source.replace('protocol.receipt(identity, sequence, raw)',
                                'protocol.receipt(identity, sequence + 1, raw)')
    candidate = tmp_path / 'fault-worker.py'
    candidate.write_text(source)
    original = LinuxAuditSink._command

    def command(self, *args):
        argv = original(self, *args)
        argv[argv.index('/app/audit_worker.py') - 1] = str(candidate)
        return argv

    monkeypatch.setattr(LinuxAuditSink, '_command', command)
    sink = LinuxAuditSink(tmp_path / 'events.jsonl')
    # Shorten only the host wait in this fixture; never weaken worker isolation.
    monkeypatch.setattr(protocol, 'EXCHANGE_SECONDS', 0.2)
    started = time.monotonic()
    with pytest.raises(AuditUnavailable):
        sink.emit({'event_type': 'execution_started'})
    assert time.monotonic() - started < 3
    assert sink._failed and sink._process.poll() is not None
    with pytest.raises(AuditUnavailable):
        sink.emit({'event_type': 'must_not_retry'})
    sink.close()


@pytest.mark.parametrize('approval_mode', ['not_required', 'denied', 'fixture_granted'])
def test_real_authority_requires_ack_before_each_owned_launch(tmp_path, approval_mode):
    policy = demo_policy(approval=approval_mode != 'not_required')
    identity, limits = str(uuid4()), SessionLimits()
    backend = AuthorizedFixtureBackend(policy, identity, limits, execute=True)
    path = tmp_path / 'events.jsonl'
    original = backend.run
    launches = []

    def run(action, policy, *, control):
        last = records(path)[-1]
        assert last['event_type'] == 'execution_started' and last['action_digest'] == action.digest
        launches.append(action.digest)
        return original(action, policy, control=control)

    backend.run = run

    def fixture_approve(controller, raw, *, control):
        # Owned grant-mechanics fixture, never represented as human approval.
        return controller.approvals.issue(parse_action(raw), policy).reference

    with LinuxAuditSink(path) as audit:
        runner = AuthoritySession(policy, audit, backend, LinuxCoordinator(), limits, session_id=identity)
        summary = runner.run(execute=True, interactive=approval_mode == 'fixture_granted',
                             approval=fixture_approve if approval_mode == 'fixture_granted' else None)
    expected = 0 if approval_mode == 'denied' else 3
    assert summary['actions_succeeded'] == len(launches) == expected
    assert audit._process.poll() == 0


@pytest.mark.parametrize('failure', ['lost_ack', 'cancel', 'deadline'])
def test_intent_persisted_but_no_launch_after_ack_loss_or_stop(tmp_path, monkeypatch, failure):
    path = tmp_path / 'events.jsonl'
    audit = LinuxAuditSink(path)
    # A launch witness only: this test does not claim backend isolation.
    backend = type('Witness', (), {'name': 'OWNED-NO-EXECUTION-WITNESS',
                                  'check_available': lambda *args: None,
                                  'run': lambda *args, **kwargs: pytest.fail('unexpected launch')})()
    controller = Controller(demo_policy(), audit, backend)
    cancelled = threading.Event()
    control = ExecutionControl(time.monotonic() + (0.3 if failure == 'deadline' else 10), cancelled)
    original = audit._reply

    def reply():
        result = original()
        if records(path)[-1]['event_type'] == 'execution_started':
            if failure == 'lost_ack':
                raise TimeoutError('owned lost acknowledgement')
            if failure == 'cancel':
                cancelled.set()
            else:
                time.sleep(max(0, control.deadline - time.monotonic()) + 0.01)
        return result

    monkeypatch.setattr(audit, '_reply', reply)
    try:
        if failure == 'lost_ack':
            with pytest.raises(AuditUnavailable):
                controller.submit(proposal(), execute=True, execution_control=control)
            assert controller._audit_failed
        else:
            outcome = controller.submit(proposal(), execute=True, execution_control=control)
            assert outcome['execution_status'] == ('cancelled' if failure == 'cancel' else 'timeout')
        assert any(row['event_type'] == 'execution_started' for row in records(path))
    finally:
        audit.close()
    assert audit._process.poll() is not None


@pytest.mark.parametrize('case,outcome', [('a', 'validated'), ('b', 'not_demonstrated'),
                                        ('c', 'inconclusive'), ('d', 'inconclusive'),
                                        ('e', 'inconclusive'), ('f', 'inconclusive')])
def test_owned_workflow_cli_preserves_evidence_with_isolated_audit(tmp_path, capsys, case, outcome):
    policy = json.loads(Path('examples/secure-agent-discovery-policy.json').read_text())
    policy['require_approval'] = False
    policy_path = tmp_path / 'policy.json'
    policy_path.write_text(json.dumps(policy))
    result = cli.main(['--workflow-assessment', case, '--fixture', '--execute', '--isolated-audit',
                       '--policy', str(policy_path), '--audit', str(tmp_path / 'events.jsonl'),
                       '--assessment-dir', str(tmp_path / 'evidence')])
    report = json.loads((tmp_path / 'evidence' / 'report.json').read_text())
    assert report['outcome'] == outcome and report['integrity_issues'] == []
    assert result in (0, 2)
    assert 'audit_error' not in capsys.readouterr().out
