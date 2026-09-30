"""Owned Linux admission boundaries; scripted PTYs are mechanics fixtures only."""

import array
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from pathlib import Path
import re
import select
import socket
import sys
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import admission_worker, launch_admission as protocol, cli
from recon_cockpit.secure_agent.admission_isolation import LinuxLaunchAdmission
from recon_cockpit.secure_agent.admitted_execution import AdmissionGatedBackend
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.authorized_execution import AuthorizedFixtureBackend
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.coordinator_isolation import LinuxCoordinator
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.planner import proposal
from recon_cockpit.secure_agent.session import SessionLimits
from scripts.secure_agent_control_plane_demo import demo_policy
from test_secure_approval_linux import terminal, read_prompt, scripted_review

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_lab():
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for actual admission isolation')
    assert sys.platform == 'linux' and os.geteuid() != 0


def instrument_worker(tmp_path, monkeypatch, transform):
    candidate = tmp_path / 'owned-admission-worker.py'
    candidate.write_text(transform(Path(admission_worker.__file__).read_text()))
    original = LinuxLaunchAdmission._command
    def command(self, *args):
        argv = original(self, *args)
        index = argv.index('/app/admission_runtime/admission_worker.py')
        argv[index - 1] = str(candidate)
        return argv
    monkeypatch.setattr(LinuxLaunchAdmission, '_command', command)


def test_actual_policy_budget_gate_and_single_use_permits():
    policy, chosen = demo_policy(), parse_action(proposal())
    control = ExecutionControl(time.monotonic()+20)
    with LinuxLaunchAdmission(policy, str(uuid4()), SessionLimits(max_steps=1), execute=True) as service:
        result = service.admit(chosen, policy, control=control)
        assert service.boundary_checks == dict.fromkeys(protocol.CHECKS, True)
        assert result['permit'] and result['reason'] is None
        assert service.redeem(result['permit'], chosen, policy, control=control)['reason'] is None
        assert service.redeem(result['permit'], chosen, policy, control=control)['reason'] == 'admission_unknown_or_replayed'
        assert service.admit(chosen, policy, control=control)['reason'] == 'admission_step_limit'
        assert dict(service.snapshot) == {'executions_reserved': 1, 'output_bytes_reserved': 1024}
        child = service._process
    assert child.poll() is not None
    with pytest.raises(IsolationUnavailable):
        service.admit(chosen, policy, control=control)


def test_worker_has_no_host_canaries_authority_or_executor_modules(tmp_path, monkeypatch):
    canary = tmp_path / 'host-canary'
    canary.write_text('OWNED-HOST-SECRET')
    monkeypatch.setenv('RECON_ADMISSION_CANARY', 'OWNED-ENV-SECRET')
    fd = os.open(canary, os.O_RDONLY)
    os.set_inheritable(fd, True)
    instrument_worker(tmp_path, monkeypatch, lambda source: source.replace(
        'checks = bootstrap._bootstrap(host)', "checks = bootstrap._bootstrap(host)\n"
        "        assert 'RECON_ADMISSION_CANARY' not in os.environ\n"
        f"        assert not os.path.exists({str(canary)!r})\n"
        "        assert set(os.listdir('/app/admission_runtime')) == {'admission_worker.py', 'launch_admission.py', 'models.py', 'tool_parameters.py', 'tool_adapters.py'}"))
    policy = demo_policy()
    try:
        with LinuxLaunchAdmission(policy, str(uuid4()), SessionLimits(), execute=True) as service:
            reply = service.admit(parse_action(proposal()), policy, control=ExecutionControl(time.monotonic()+20))
            assert reply['permit'] and 'SECRET' not in protocol.encode(reply).decode()
    finally:
        os.close(fd)


@pytest.mark.parametrize('change', ['action', 'policy', 'expiry', 'restart'])
def test_actual_binding_expiry_and_restart_fail_closed(change):
    policy, chosen = demo_policy(), parse_action(proposal())
    session_id, control = str(uuid4()), ExecutionControl(time.monotonic()+20)
    with LinuxLaunchAdmission(policy, session_id, SessionLimits(), execute=True) as service:
        permit = service.admit(chosen, policy, control=control)['permit']
        if change == 'restart':
            with LinuxLaunchAdmission(policy, session_id, SessionLimits(), execute=True) as other:
                other.admit(chosen, policy, control=control)
                assert other.redeem(permit, chosen, policy, control=control)['reason'] == 'admission_unknown_or_replayed'
            return
        if change == 'expiry':
            time.sleep(protocol.PERMIT_SECONDS + 0.05)
        result = service.redeem(permit, replace(chosen, rationale='changed') if change == 'action' else chosen,
                               replace(policy, policy_version='changed') if change == 'policy' else policy,
                               control=control)
        assert result['reason'] == {'action': 'admission_action_changed', 'policy': 'admission_policy_changed',
                                     'expiry': 'admission_expired'}[change]
        assert service.redeem(permit, chosen, policy, control=control)['reason'] == 'admission_unknown_or_replayed'


@pytest.mark.parametrize('malice', ['replay', 'session', 'service', 'reset', 'boolean', 'budget',
                                    'extra_fd', 'oversized', 'duplicate'])
def test_worker_rejects_forged_authority_requests(malice):
    policy, chosen = demo_policy(), parse_action(proposal())
    control = ExecutionControl(time.monotonic()+20)
    with LinuxLaunchAdmission(policy, str(uuid4()), SessionLimits(), execute=True) as service:
        service.admit(chosen, policy, control=control)
        value = {'version': '1', 'service_id': service._config['service_id'],
            'session_id': service._config['session_id'], 'sequence': 2, 'operation': 'admit',
            'action': chosen.to_dict(), 'policy_digest': policy.digest}
        if malice == 'replay':
            value['sequence'] = 1
        elif malice == 'session':
            value['session_id'] = str(uuid4())
        elif malice == 'service':
            value['service_id'] = str(uuid4())
        elif malice == 'reset':
            value['operation'] = 'reset'
        elif malice == 'boolean':
            value['approved'] = True
        elif malice == 'budget':
            value['output_reserved_before'] = 0
        raw = protocol.encode(value)
        if malice == 'oversized':
            raw = b'x' * (protocol.MAX_PACKET + 1)
        elif malice == 'duplicate':
            raw = b'{"version":"1",' + raw[1:]
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [1]))] if malice == 'extra_fd' else []
        service._channel.sendmsg([raw], ancillary)
        assert service._process.wait(timeout=5) == 78
        with pytest.raises(IsolationUnavailable):
            service.admit(chosen, policy, control=control)
        assert service._closed


@pytest.mark.parametrize('failure', ['bad_ready', 'bad_receipt', 'flood', 'worker_exit',
                                     'lost_admit', 'lost_redeem', 'cancel', 'timeout'])
def test_failure_never_reaches_underlying_executor(tmp_path, monkeypatch, failure):
    policy, chosen = demo_policy(), parse_action(proposal())
    control = ExecutionControl(time.monotonic()+(1.5 if failure == 'timeout' else 20), threading.Event())
    underlying = AuthorizedFixtureBackend(policy, str(uuid4()), SessionLimits(), execute=True)
    launches = []
    monkeypatch.setattr(underlying, 'run', lambda *_a, **_k: launches.append(True))
    if failure == 'bad_ready':
        instrument_worker(tmp_path, monkeypatch, lambda source: source.replace(
            "'ready': True, 'checks': checks", "'ready': True, 'checks': {}"))
    if failure == 'bad_receipt':
        instrument_worker(tmp_path, monkeypatch, lambda source: source.replace(
            'protocol.receipt(value, outcome)', "{**protocol.receipt(value, outcome), 'sequence': 999}"))
    if failure == 'flood':
        instrument_worker(tmp_path, monkeypatch, lambda source: source.replace(
            'outcome = state.handle(value)', "print('X' * 70000, flush=True)\n            outcome = state.handle(value)"))
    if failure in ('cancel', 'timeout'):
        instrument_worker(tmp_path, monkeypatch, lambda source: source.replace(
            'outcome = state.handle(value)', 'time.sleep(30)\n            outcome = state.handle(value)'))
    with AdmissionGatedBackend(underlying) as gate:
        service = gate._admission
        original = service._reply
        replies = []
        def reply():
            value = original()
            replies.append(value)
            if len(replies) == 2:
                if failure == 'worker_exit':
                    service._process.kill()
                    service._process.wait(timeout=2)
                if failure == 'lost_admit':
                    raise TimeoutError('OWNED-LOST-ADMIT')
            if len(replies) == 3 and failure == 'lost_redeem':
                raise TimeoutError('OWNED-LOST-REDEEM')
            return value
        monkeypatch.setattr(service, '_reply', reply)
        timer = threading.Timer(0.8, control.cancelled.set)
        if failure == 'cancel':
            timer.start()
        try:
            with pytest.raises((IsolationUnavailable, ExecutionStopped)):
                gate.run(chosen, policy, control=control)
        finally:
            if failure == 'cancel':
                timer.join()
        assert launches == [] and service._closed
        assert service._process.poll() is not None
        with pytest.raises(IsolationUnavailable):
            gate.run(chosen, policy, control=ExecutionControl(time.monotonic()+20))


def test_host_executor_counter_reset_cannot_replenish_admission_budget():
    policy, chosen = demo_policy(), parse_action(proposal())
    control = ExecutionControl(time.monotonic()+20)
    underlying = AuthorizedFixtureBackend(policy, str(uuid4()), SessionLimits(max_steps=1), execute=True)
    with AdmissionGatedBackend(underlying) as gate:
        assert gate.run(chosen, policy, control=control)['status'] == 'succeeded'
        # An internal launcher counter change cannot refund independently held
        # admission state. This does not claim containment of the host user.
        underlying._sequence = underlying._output = 0
        with pytest.raises(IsolationUnavailable):
            gate.run(chosen, policy, control=control)
        assert underlying.snapshot['executions_reserved'] == 0
        assert gate.admission_snapshot['executions_reserved'] == 1


def test_actual_authority_composes_approval_audit_admission_and_executor(tmp_path, terminal):
    policy = demo_policy(approval=True)
    session_id, limits = str(uuid4()), SessionLimits()
    path = tmp_path / 'events.jsonl'
    underlying = AuthorizedFixtureBackend(policy, session_id, limits, execute=True)
    launches = []
    original = underlying.run
    with AdmissionGatedBackend(underlying) as gate, LinuxApprovalService(policy, session_id) as approvals, LinuxAuditSink(path) as audit:
        def run(chosen, supplied_policy, *, control):
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            assert rows[-1]['event_type'] == 'execution_started'
            assert rows[-2]['event_type'] == 'approval_consumed'
            assert gate._admission._sequence == 2 * (len(launches) + 1)
            assert gate.admission_snapshot['executions_reserved'] == len(launches) + 1
            launches.append(chosen.digest)
            return original(chosen, supplied_policy, control=control)
        underlying.run = run
        runner = AuthoritySession(policy, audit, gate, LinuxCoordinator(), limits, session_id=session_id, approvals=approvals)
        def fixture_review(controller, raw, *, control):
            return scripted_review(approvals, parse_action(raw), policy, terminal, control)[0]
        summary = runner.run(execute=True, interactive=True, approval=fixture_review)
        assert summary['stop_reason'] == 'coordinator_done' and summary['actions_succeeded'] == len(launches) == 3
    assert gate._admission._process.poll() is not None
    assert approvals._process.poll() is not None and audit._process.poll() == 0


@pytest.mark.parametrize('case,outcome', [('a', 'validated'), ('b', 'not_demonstrated'), ('c', 'inconclusive'),
                                        ('d', 'inconclusive'), ('e', 'inconclusive'), ('f', 'inconclusive')])
def test_owned_workflow_cli_with_all_boundaries(tmp_path, monkeypatch, capsys, terminal, case, outcome):
    run_workflow(tmp_path, monkeypatch, capsys, terminal, case, outcome, '--fixture')


def test_persistent_owned_lab_cli_with_all_boundaries(tmp_path, monkeypatch, capsys, terminal):
    run_workflow(tmp_path, monkeypatch, capsys, terminal, 'a', 'validated', '--owned-lab')


def run_workflow(tmp_path, monkeypatch, capsys, terminal, case, outcome, backend):
    import termios
    attrs = termios.tcgetattr(terminal)
    attrs[3] &= ~termios.ECHO
    termios.tcsetattr(terminal, termios.TCSANOW, attrs)
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(cli.sys.stdout, 'isatty', lambda: True)
    stopped, prompts = threading.Event(), []
    def respond():
        while not stopped.is_set():
            if not select.select([terminal], [], [], 0.05)[0]:
                continue
            prompt = read_prompt(terminal)
            challenge = re.search(rb"Type '(approve [0-9a-f]{16} [0-9a-f]{32})'", prompt).group(1)
            prompts.append(prompt)
            os.write(terminal, challenge+b'\n')
    with ThreadPoolExecutor(max_workers=1) as pool:
        replying = pool.submit(respond)
        try:
            status = cli.main(['--workflow-assessment', case, backend, '--execute', '--isolated-audit',
                '--isolated-approvals', '--isolated-launch-admission', '--policy', 'examples/secure-agent-discovery-policy.json',
                '--audit', str(tmp_path/'events.jsonl'), '--assessment-dir', str(tmp_path/'evidence')])
        finally:
            stopped.set()
        replying.result(timeout=10)
    report = json.loads((tmp_path/'evidence'/'report.json').read_text())
    assert report['outcome'] == outcome and report['integrity_issues'] == []
    assert 2 <= len(prompts) <= 3 and status in (0, 2)
    assert 'isolation_unavailable' not in capsys.readouterr().out


def test_changed_bootstrap_cannot_select_policy_or_deadline(monkeypatch):
    policy = demo_policy()
    with LinuxLaunchAdmission(policy, str(uuid4()), SessionLimits(), execute=True) as service:
        original = service._send
        def send(raw):
            value = protocol.decode(raw)
            if 'configuration' in value:
                value['configuration']['limits']['max_steps'] = 16
            original(protocol.encode(value))
        monkeypatch.setattr(service, '_send', send)
        with pytest.raises(IsolationUnavailable):
            service.admit(parse_action(proposal()), policy, control=ExecutionControl(time.monotonic()+20))
        assert service._closed and service._process.poll() is not None


@pytest.mark.parametrize('failure', ['denied_approval', 'lost_audit_ack'])
def test_consent_or_durability_failure_never_starts_admission(tmp_path, terminal, monkeypatch, failure):
    from recon_cockpit.secure_agent.audit import AuditUnavailable
    policy = demo_policy(approval=True)
    session_id, limits = str(uuid4()), SessionLimits()
    path = tmp_path/'events.jsonl'
    underlying = AuthorizedFixtureBackend(policy, session_id, limits, execute=True)
    launches = []
    monkeypatch.setattr(underlying, 'run', lambda *_a, **_k: launches.append(True))
    with AdmissionGatedBackend(underlying) as gate, LinuxApprovalService(policy, session_id) as approvals, LinuxAuditSink(path) as audit:
        original = audit.emit
        def emit(event):
            original(event)
            if event['event_type'] == 'execution_started' and failure == 'lost_audit_ack':
                raise AuditUnavailable('OWNED-LOST-AUDIT-ACK')
        monkeypatch.setattr(audit, 'emit', emit)
        runner = AuthoritySession(policy, audit, gate, LinuxCoordinator(), limits,
                                  session_id=session_id, approvals=approvals)
        def fixture_review(controller, raw, *, control):
            return scripted_review(approvals, parse_action(raw), policy, terminal, control,
                                     b'' if failure == 'denied_approval' else None)[0]
        if failure == 'lost_audit_ack':
            with pytest.raises(AuditUnavailable):
                runner.run(execute=True, interactive=True, approval=fixture_review)
        else:
            summary = runner.run(execute=True, interactive=True, approval=fixture_review)
            assert summary['stop_reason'] == 'action_blocked'
        assert launches == [] and gate._admission._control is None
        assert not hasattr(gate._admission, '_process')
    assert approvals._process.poll() is not None and audit._process.poll() == 0
