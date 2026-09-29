"""Owned scripted PTYs test grant mechanics, not real human approval evidence."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from pathlib import Path
import pty
import re
import select
import sys
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import approval_isolation, approval_protocol as protocol, approval_worker, cli
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.approvals import ApprovalUnavailable
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.authorized_execution import AuthorizedFixtureBackend
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.coordinator_isolation import LinuxCoordinator
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.session import SessionLimits
from scripts.secure_agent_control_plane_demo import demo_policy

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_lab():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for isolated approval fixtures')
    assert sys.platform == 'linux' and os.geteuid() != 0


@pytest.fixture
def terminal(monkeypatch):
    master, slave = pty.openpty()
    os.set_blocking(slave, False)
    monkeypatch.setattr(approval_isolation, '_open_terminal', lambda: os.dup(slave))
    try:
        yield master
    finally:
        os.close(slave)
        os.close(master)


def read_prompt(master):
    output = bytearray()
    deadline = time.monotonic() + 8
    while b'(blank denies): ' not in output:
        assert select.select([master], [], [], max(0, deadline - time.monotonic()))[0], output
        output.extend(os.read(master, 4096))
        assert len(output) < 8192
    return output


def scripted_review(service, proposed, policy, master, control, answer=None):
    def respond():
        prompt = read_prompt(master)
        challenge = re.search(rb"Type '(approve [0-9a-f]{16} [0-9a-f]{32})'", prompt).group(1)
        os.write(master, (challenge if answer is None else answer) + b'\n')
        return prompt
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(respond)
        reference = service.review(proposed, policy, control=control)
        return reference, pending.result(timeout=5)


def action():
    return parse_action({'schema_version': '1', 'action_id': str(uuid4()), 'tool_id': 'http_probe',
        'target': '127.0.0.1', 'parameters': {'port': 8080, 'method': 'GET', 'path': '/',
        'timeout_seconds': 1, 'max_output_bytes': 1024}, 'rationale': 'untrusted-hidden-rationale'})


def test_real_worker_review_binding_single_use_and_cleanup(terminal):
    policy = demo_policy(approval=True)
    proposed = action()
    control = ExecutionControl(time.monotonic() + 20)
    with LinuxApprovalService(policy, str(uuid4())) as service:
        assert service.boundary_checks is None
        ref, prompt = scripted_review(service, proposed, policy, terminal, control)
        assert ref is not None
        assert proposed.digest.encode() in prompt and policy.digest.encode() in prompt
        assert b'untrusted-hidden-rationale' not in prompt
        assert service.boundary_checks == dict.fromkeys(protocol.CHECKS, True)
        assert service.consume(ref, proposed, policy) is None
        assert service.consume(ref, proposed, policy) == 'approval_unknown_or_replayed'
        child = service._process
    assert child.poll() is not None
    with pytest.raises(ApprovalUnavailable):
        service.consume(ref, proposed, policy)


@pytest.mark.parametrize('answer', [b'', b'approve', b'approve 0000000000000000', b'x' * 128])
def test_wrong_or_bounded_answer_never_issues(terminal, answer):
    policy = demo_policy(approval=True)
    with LinuxApprovalService(policy, str(uuid4())) as service:
        ref, _ = scripted_review(service, action(), policy, terminal,
                                 ExecutionControl(time.monotonic() + 15), answer)
        assert ref is None


@pytest.mark.parametrize('change', ['action', 'policy', 'expiry', 'new_worker'])
def test_changed_or_expired_grants_burn_and_do_not_survive_restart(terminal, change):
    policy = replace(demo_policy(approval=True), approval_ttl_seconds=1 if change == 'expiry' else 60)
    proposed = action()
    control = ExecutionControl(time.monotonic() + 20)
    session_id = str(uuid4())
    with LinuxApprovalService(policy, session_id) as service:
        ref, _ = scripted_review(service, proposed, policy, terminal, control)
        assert ref
        if change == 'new_worker':
            with LinuxApprovalService(policy, session_id) as other:
                scripted_review(other, proposed, policy, terminal, control, b'')
                assert other.consume(ref, proposed, policy) == 'approval_unknown_or_replayed'
            return
        if change == 'expiry':
            time.sleep(1.05)
        result = service.consume(ref, replace(proposed, rationale='changed') if change == 'action' else proposed,
                                 replace(policy, policy_version='changed') if change == 'policy' else policy)
        assert result == {'action': 'approval_action_changed', 'policy': 'approval_policy_changed',
                          'expiry': 'approval_expired'}[change]
        assert service.consume(ref, proposed, policy) == 'approval_unknown_or_replayed'


@pytest.mark.parametrize('cancel', [True, False])
def test_terminal_wait_is_bounded_and_child_reaped(terminal, cancel):
    policy = demo_policy(approval=True)
    stopped = threading.Event()
    control = ExecutionControl(time.monotonic() + (15 if cancel else 1.5), stopped)
    with LinuxApprovalService(policy, str(uuid4())) as service, ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(service.review, action(), policy, control=control)
        read_prompt(terminal)
        if cancel:
            stopped.set()
        with pytest.raises(ExecutionStopped) as error:
            pending.result(timeout=5)
        assert error.value.reason == ('session_cancelled' if cancel else 'session_timeout')
        assert service._process.poll() is not None
        with pytest.raises(ApprovalUnavailable):
            service.review(action(), policy, control=ExecutionControl(time.monotonic() + 15))


def instrument_worker(tmp_path, monkeypatch, transform):
    source = transform(Path(approval_worker.__file__).read_text())
    candidate = tmp_path / 'owned-approval-worker.py'
    candidate.write_text(source)
    original = LinuxApprovalService._command
    def command(self, *args):
        argv = original(self, *args)
        index = argv.index('/app/approval_runtime/approval_worker.py')
        argv[index - 1] = str(candidate)
        return argv
    monkeypatch.setattr(LinuxApprovalService, '_command', command)


def test_host_canaries_files_and_inheritable_fd_are_absent(tmp_path, monkeypatch, terminal):
    canary = tmp_path / 'host-secret'
    canary.write_text('OWNED-HOST-CANARY')
    monkeypatch.setenv('RECON_APPROVAL_HOST_CANARY', 'OWNED-ENV-CANARY')
    fd = os.open(canary, os.O_RDONLY)
    os.set_inheritable(fd, True)
    instrument_worker(tmp_path, monkeypatch, lambda source: source.replace(
        'checks = bootstrap._bootstrap(host)',
        "checks = bootstrap._bootstrap(host)\n"
        "        assert 'RECON_APPROVAL_HOST_CANARY' not in os.environ\n"
        f"        assert not os.path.exists({str(canary)!r})\n"
        "        assert not os.path.exists('/app/approval_runtime/controller.py')\n"
        "        assert not os.path.exists('/app/approval_runtime/audit.py')"))
    policy = demo_policy(approval=True)
    try:
        with LinuxApprovalService(policy, str(uuid4())) as service:
            ref, prompt = scripted_review(service, action(), policy, terminal,
                                          ExecutionControl(time.monotonic() + 15))
            assert ref and b'CANARY' not in prompt
    finally:
        os.close(fd)


def test_pretyped_input_flushed_and_old_challenge_cannot_approve_again(terminal):
    policy, proposed = demo_policy(approval=True), action()
    control = ExecutionControl(time.monotonic() + 15)
    with LinuxApprovalService(policy, str(uuid4())) as service:
        os.write(terminal, b'pretyped answer must be discarded\n')
        ref, first = scripted_review(service, proposed, policy, terminal, control)
        assert ref
        assert service.consume(ref, proposed, policy) is None
        old = re.search(rb"Type '(approve [0-9a-f]{16} [0-9a-f]{32})'", first).group(1)
        ref, second = scripted_review(service, proposed, policy, terminal, control, old)
        assert ref is None
        fresh = re.search(rb"Type '(approve [0-9a-f]{16} [0-9a-f]{32})'", second).group(1)
        assert fresh != old


@pytest.mark.parametrize('malice', ['replay', 'session', 'broker', 'issue', 'reset', 'boolean',
                                    'policy', 'denied_action', 'extra_fd', 'oversized', 'duplicate'])
def test_real_worker_refuses_forged_messages_and_never_mints(tmp_path, terminal, malice):
    import array
    import socket
    policy, proposed = demo_policy(approval=True), action()
    with LinuxApprovalService(policy, str(uuid4())) as service:
        control = ExecutionControl(time.monotonic() + 15)
        scripted_review(service, proposed, policy, terminal, control, b'')
        value = {'version': '1', 'broker_id': service._identity, 'session_id': service._session_id,
                 'sequence': 2, 'operation': 'review', 'action': proposed.to_dict(), 'policy_digest': policy.digest}
        if malice == 'replay':
            value['sequence'] = 1
        elif malice == 'session':
            value['session_id'] = str(uuid4())
        elif malice == 'broker':
            value['broker_id'] = str(uuid4())
        elif malice in ('issue', 'reset'):
            value['operation'] = malice
        elif malice == 'boolean':
            value['approved'] = True
        elif malice == 'policy':
            value['policy_digest'] = '0' * 64
        elif malice == 'denied_action':
            value['action']['target'] = '192.0.2.1'
        raw = protocol.encode(value)
        if malice == 'oversized':
            raw = b'x' * (protocol.MAX_PACKET + 1)
        elif malice == 'duplicate':
            raw = b'{"version":"1",' + raw[1:]
        ancillary = []
        if malice == 'extra_fd':
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [terminal]))]
        service._channel.sendmsg([raw], ancillary)
        assert service._process.wait(timeout=5) == 78
        with pytest.raises(ApprovalUnavailable):
            service.consume('0' * 48, proposed, policy)
        assert service._closed


def test_worker_review_count_bound(terminal):
    policy, proposed = demo_policy(approval=True), action()
    control = ExecutionControl(time.monotonic() + 15)
    with LinuxApprovalService(policy, str(uuid4())) as service:
        for _ in range(16):
            ref, _ = scripted_review(service, proposed, policy, terminal, control, b'')
            assert ref is None
        with pytest.raises(ApprovalUnavailable):
            service.review(proposed, policy, control=control)
        assert service._closed and service._process.poll() is not None


@pytest.mark.parametrize('failure', ['no_tty', 'regular_file', 'bad_ready', 'worker_exit', 'lost_receipt'])
def test_terminal_bootstrap_or_worker_fault_permanently_closes(tmp_path, monkeypatch, terminal, failure):
    policy, proposed = demo_policy(approval=True), action()
    control = ExecutionControl(time.monotonic() + 15)
    with LinuxApprovalService(policy, str(uuid4())) as service:
        if failure == 'no_tty':
            def absent():
                raise OSError('OWNED-PRIVATE-DETAIL')
            monkeypatch.setattr(approval_isolation, '_open_terminal', absent)
        elif failure == 'regular_file':
            path = tmp_path / 'not-a-terminal'
            path.touch()
            monkeypatch.setattr(approval_isolation, '_open_terminal',
                                lambda: os.open(path, os.O_RDWR | os.O_NONBLOCK))
        elif failure == 'bad_ready':
            instrument_worker(tmp_path, monkeypatch, lambda source: source.replace(
                "'ready': True, 'checks': checks", "'ready': True, 'checks': {}"))
        else:
            ref, _ = scripted_review(service, proposed, policy, terminal, control)
            assert ref
            if failure == 'worker_exit':
                service._process.kill()
                service._process.wait(timeout=2)
            else:
                original = service._reply
                def lose_reply():
                    original()
                    raise TimeoutError('OWNED-PRIVATE-DETAIL')
                monkeypatch.setattr(service, '_reply', lose_reply)
        with pytest.raises(ApprovalUnavailable) as error:
            if failure in ('worker_exit', 'lost_receipt'):
                service.consume(ref, proposed, policy)
            else:
                service.review(proposed, policy, control=control)
        assert str(error.value) == 'approval_unavailable'
        with pytest.raises(ApprovalUnavailable):
            service.review(proposed, policy, control=control)
        assert service._closed
        if hasattr(service, '_process'):
            assert service._process.poll() is not None


def test_real_authority_grant_consumption_and_durable_intent_before_owned_launch(tmp_path, terminal):
    policy = demo_policy(approval=True)
    session_id, limits = str(uuid4()), SessionLimits()
    path = tmp_path / 'audit.jsonl'
    backend = AuthorizedFixtureBackend(policy, session_id, limits, execute=True)
    run = backend.run
    launches = []
    def checked_run(proposed, policy, *, control):
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        assert rows[-1]['event_type'] == 'execution_started'
        assert rows[-2]['event_type'] == 'approval_consumed'
        assert rows[-1]['action_digest'] == rows[-2]['action_digest'] == proposed.digest
        launches.append(proposed.digest)
        return run(proposed, policy, control=control)
    backend.run = checked_run
    with LinuxApprovalService(policy, session_id) as approvals, LinuxAuditSink(path) as audit:
        runner = AuthoritySession(policy, audit, backend, LinuxCoordinator(), limits,
                                  session_id=session_id, approvals=approvals)
        def fixture_review(controller, raw, *, control):
            return scripted_review(approvals, parse_action(raw), policy, terminal, control)[0]
        result = runner.run(execute=True, interactive=True, approval=fixture_review)
        assert result['stop_reason'] == 'coordinator_done'
        assert result['actions_succeeded'] == len(launches) == 3
    assert approvals._process.poll() is not None and audit._process.poll() == 0


@pytest.mark.parametrize('case,outcome', [('a', 'validated'), ('b', 'not_demonstrated'),
    ('c', 'inconclusive'), ('d', 'inconclusive'), ('e', 'inconclusive'), ('f', 'inconclusive')])
def test_owned_workflow_cli_with_both_isolated_services(tmp_path, monkeypatch, capsys, terminal, case, outcome):
    policy_path = Path('examples/secure-agent-discovery-policy.json')
    assert json.loads(policy_path.read_text())['require_approval'] is True
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(cli.sys.stdout, 'isatty', lambda: True)
    prompts = []
    stop = threading.Event()
    def respond():
        while not stop.is_set():
            if not select.select([terminal], [], [], 0.05)[0]:
                continue
            prompt = read_prompt(terminal)
            prompts.append(prompt)
            challenge = re.search(rb"Type '(approve [0-9a-f]{16} [0-9a-f]{32})'", prompt).group(1)
            os.write(terminal, challenge + b'\n')
    # Disable echo only in this owned PTY fixture, keeping a readback of typed
    # answers from becoming the responder's next prompt.
    import termios
    attrs = termios.tcgetattr(terminal)
    attrs[3] &= ~termios.ECHO
    termios.tcsetattr(terminal, termios.TCSANOW, attrs)
    with ThreadPoolExecutor(max_workers=1) as pool:
        responding = pool.submit(respond)
        try:
            result = cli.main(['--workflow-assessment', case, '--fixture', '--execute',
                '--isolated-audit', '--isolated-approvals', '--policy', str(policy_path),
                '--audit', str(tmp_path / 'audit.jsonl'), '--assessment-dir', str(tmp_path / 'evidence')])
        finally:
            stop.set()
        responding.result(timeout=10)
    report = json.loads((tmp_path / 'evidence' / 'report.json').read_text())
    assert report['outcome'] == outcome and report['integrity_issues'] == []
    assert result in (0, 2)
    records = [json.loads(line) for line in (tmp_path / 'audit.jsonl').read_text().splitlines()]
    launches = [row for row in records if row['event_type'] == 'execution_started']
    grants = [row for row in records if row['event_type'] == 'approval_consumed']
    assert 2 <= len(prompts) == len(launches) == len(grants) <= 3
    assert [row['action_digest'] for row in launches] == [row['action_digest'] for row in grants]
    assert 'approval_unavailable' not in capsys.readouterr().out


@pytest.mark.parametrize('failure,expected', [
    ('deny', 'action_blocked'), ('lost_receipt', 'approval_unavailable'),
    ('cancel', 'session_cancelled'), ('timeout', 'session_timeout')])
def test_real_authority_approval_fault_or_stop_prevents_every_launch(tmp_path, terminal, monkeypatch,
                                                                   failure, expected):
    policy = demo_policy(approval=True)
    session_id = str(uuid4())
    limits = SessionLimits(max_runtime_seconds=2 if failure == 'timeout' else 20)
    path = tmp_path / 'audit.jsonl'
    backend = AuthorizedFixtureBackend(policy, session_id, limits, execute=True)
    monkeypatch.setattr(backend, 'run', lambda *_a, **_k: pytest.fail('must not launch'))
    with LinuxApprovalService(policy, session_id) as approvals, LinuxAuditSink(path) as audit:
        runner = AuthoritySession(policy, audit, backend, LinuxCoordinator(), limits,
                                  session_id=session_id, approvals=approvals)
        def fixture_review(controller, raw, *, control):
            proposed = parse_action(raw)
            if failure in ('deny', 'lost_receipt'):
                ref, _ = scripted_review(approvals, proposed, policy, terminal, control,
                                          b'' if failure == 'deny' else None)
                if failure == 'lost_receipt':
                    original = approvals._reply
                    def lose_reply():
                        original()
                        raise TimeoutError('OWNED-PRIVATE-RECEIPT')
                    monkeypatch.setattr(approvals, '_reply', lose_reply)
                return ref
            def stop_after_prompt():
                read_prompt(terminal)
                if failure == 'cancel':
                    runner.cancel()
            with ThreadPoolExecutor(max_workers=1) as pool:
                stopping = pool.submit(stop_after_prompt)
                try:
                    return approvals.review(proposed, policy, control=control)
                finally:
                    stopping.result(timeout=5)
        summary = runner.run(execute=True, interactive=True, approval=fixture_review)
        assert summary['stop_reason'] == expected and summary['actions_succeeded'] == 0
        assert summary['output_reserved_bytes'] == 1024
    assert approvals._process.poll() is not None and audit._process.poll() == 0
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert records[-1]['event_type'] == 'session_finished' and records[-1]['stop_reason'] == expected
    assert not any(row['event_type'] == 'execution_started' for row in records)
    assert 'OWNED-PRIVATE-RECEIPT' not in path.read_text()
