"""Protocol and host wiring tests; doubles here are not isolation evidence."""

from dataclasses import replace
import json
from types import SimpleNamespace
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import approval_isolation, approval_protocol as protocol, cli
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.approvals import ApprovalUnavailable
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.planner import proposal
from scripts.secure_agent_control_plane_demo import demo_policy


def request(operation='review'):
    return {'version': '1', 'broker_id': str(uuid4()), 'session_id': str(uuid4()), 'sequence': 1,
            'operation': operation, 'action': proposal(), 'policy_digest': 'a' * 64,
            **({'reference': 'b' * 48} if operation == 'consume' else {})}


@pytest.mark.parametrize('change', [
    {'version': 1}, {'sequence': True}, {'sequence': 0}, {'sequence': 2},
    {'broker_id': str(uuid4())}, {'session_id': str(uuid4())}, {'operation': 'issue'},
    {'operation': 'reset'}, {'operation': 'update_policy'}, {'operation': []},
    {'policy_digest': 'X' * 64}, {'policy_digest': None}, {'policy_digest': True},
    {'approved': True}, {'reference': 'b' * 48}, {'terminal': '/dev/tty'}, {'action': {}},
])
def test_request_rejects_forgery_or_identity_change(change):
    value = request()
    broker, session = value['broker_id'], value['session_id']
    value.update(change)
    with pytest.raises(ValueError):
        protocol.request(value, broker, session, 1)


@pytest.mark.parametrize('reference', ['', 'x' * 48, 'a' * 47, 'a' * 49, True, 1, [], {}])
def test_invalid_grant_reference(reference):
    value = request('consume')
    value['reference'] = reference
    with pytest.raises(ValueError):
        protocol.request(value, value['broker_id'], value['session_id'], 1)


@pytest.mark.parametrize('raw', [b'{}' * 2, b'[]', b'{"x":1,"x":2}', b'{"x":NaN}', b'x' * 32769,
                                b'{"x":"\xff"}', b'', '{}'])
def test_strict_transport(raw):
    with pytest.raises(ValueError):
        protocol.decode(raw)


@pytest.mark.parametrize('change', [
    {'deadline': True}, {'deadline': float('inf')}, {'deadline': 1}, {'deadline': 1000},
    {'version': '2'}, {'terminal': [1, 2]}, {'terminal': [True, 2, 3]},
    {'terminal': [-1, 2, 3]}, {'session_id': 'other'}, {'policy': {}}, {'approved': True},
])
def test_bootstrap_is_bounded_fixed_policy_and_session(change):
    value = {'version': '1', 'broker_id': str(uuid4()), 'session_id': str(uuid4()),
             'policy': demo_policy(approval=True).to_dict(), 'deadline': 50, 'terminal': [1, 2, 3]}
    value.update(change)
    with pytest.raises(ValueError):
        protocol.initial(value, 10)


def test_inert_constructor_unknown_reference_and_close_never_open_terminal(monkeypatch):
    monkeypatch.setattr(approval_isolation, '_open_terminal', lambda: pytest.fail('unexpected terminal'))
    monkeypatch.setattr(LinuxApprovalService, '_start', lambda *_: pytest.fail('unexpected launch'))
    with LinuxApprovalService(demo_policy(approval=True), str(uuid4())) as service:
        assert service.consume(None, parse_action(proposal()), service._policy) == 'approval_missing'
        assert service.consume('a' * 48, parse_action(proposal()), service._policy) == 'approval_unknown_or_replayed'
        assert service.boundary_checks is None
    with pytest.raises(ApprovalUnavailable):
        service.review(parse_action(proposal()), service._policy, control=ExecutionControl(time.monotonic() + 10))


@pytest.mark.parametrize('change', [
    {'sequence': 0}, {'broker_id': str(uuid4())}, {'session_id': str(uuid4())},
    {'result': True}, {'result': 'x' * 48}, {'request_digest': '0' * 64}, {'extra': False},
])
def test_bad_receipt_poisoned_without_retry_or_local_fallback(monkeypatch, change):
    policy = demo_policy(approval=True)
    service = LinuxApprovalService(policy, str(uuid4()))
    control = ExecutionControl(time.monotonic() + 10)
    sent = []
    service._control = control
    service._supervisor = SimpleNamespace(deadline=control.deadline, close=lambda: None)
    monkeypatch.setattr(service, '_quiet', lambda: None)
    monkeypatch.setattr(service, '_send', lambda raw: sent.append(protocol.decode(raw)))
    monkeypatch.setattr(service, '_reply', lambda: {**protocol.receipt(sent[-1], 'b' * 48), **change})
    with pytest.raises(ApprovalUnavailable):
        service.review(parse_action(proposal()), policy, control=control)
    with pytest.raises(ApprovalUnavailable):
        service.review(parse_action(proposal()), policy, control=control)
    assert len(sent) == 1 and service._closed


def test_request_limit_and_control_cannot_be_renewed(monkeypatch):
    policy = demo_policy(approval=True)
    control = ExecutionControl(time.monotonic() + 10)
    for changed_control in (False, True):
        with LinuxApprovalService(policy, str(uuid4())) as service:
            service._control = control
            service._sequence = 32 if not changed_control else 0
            service._supervisor = SimpleNamespace(deadline=control.deadline, close=lambda: None)
            monkeypatch.setattr(service, '_send', lambda *_: pytest.fail('must not send'))
            with pytest.raises(ApprovalUnavailable):
                service.review(parse_action(proposal()), policy,
                               control=replace(control) if changed_control else control)


@pytest.mark.parametrize('source', [[], ['--mock'], ['--session-mock', 'three_step'],
    ['--isolated-session-mock', 'three_step'], ['--openai-offline', 'three_step'],
    ['--inspect-assessment', '/missing'], ['--inspect-evaluation', '/missing'],
    ['--evaluate-owned-lab'], ['--proposal', '/missing']])
def test_cli_rejects_unsupported_modes_before_io(monkeypatch, source):
    monkeypatch.setattr(cli, '_read_bounded', lambda *_: pytest.fail('must not read'))
    with pytest.raises(SystemExit) as error:
        cli.main([*source, '--isolated-approvals'])
    assert error.value.code == 2


@pytest.mark.parametrize('stdin,stdout', [(False, True), (True, False), (False, False)])
def test_noninteractive_ui_never_parses_or_starts(monkeypatch, stdin, stdout):
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: stdin)
    monkeypatch.setattr(cli.sys.stdout, 'isatty', lambda: stdout)
    monkeypatch.setattr(cli, 'parse_action', lambda *_: pytest.fail('must not parse'))
    assert cli._isolated_human_approval(None, b'bad', control=None) is None


@pytest.mark.parametrize('failure_stage,swallow', [('review', False), ('review', True),
                                                   ('consume', False), ('consume', True)])
def test_authority_approval_failure_is_sticky_audited_and_never_launches(tmp_path, failure_stage, swallow):
    policy = demo_policy(approval=True)
    class BrokenApprovals:
        def consume(self, *_):
            raise ApprovalUnavailable('private detail')
    class Coordinator:
        def run(self, initial, exchange, *, control):
            initial = json.loads(initial)
            raw = json.dumps({**initial, 'sequence': 1,
                'plan': {'schema_version': '1', 'action': proposal(), 'done': True}}).encode()
            try:
                exchange(raw, control=control)
            except ApprovalUnavailable:
                if not swallow:
                    raise
            return json.dumps({**initial, 'status': 'closed'}).encode()
    def review(*_args, **_kwargs):
        if failure_stage == 'review':
            raise ApprovalUnavailable('private detail')
        return 'b' * 48
    backend = SimpleNamespace(check_available=lambda *_: pytest.fail('must not check or launch'))
    path = tmp_path / 'audit.jsonl'
    with AuditSink(path) as audit:
        runner = AuthoritySession(policy, audit, backend, Coordinator(), approvals=BrokenApprovals())
        result = runner.run(execute=True, interactive=True, approval=review)
        assert result['stop_reason'] == 'approval_unavailable' and result['actions_succeeded'] == 0
        with pytest.raises(ApprovalUnavailable):
            runner.controller.submit(proposal())
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert records[-1]['stop_reason'] == 'approval_unavailable'
    assert not any(row['event_type'] == 'execution_started' for row in records)
    assert 'private detail' not in path.read_text()


def test_controller_consumption_fault_poisoned_even_without_session(tmp_path):
    policy = demo_policy(approval=True)
    class BrokenApprovals:
        def consume(self, *_):
            raise ApprovalUnavailable()
    with AuditSink(tmp_path / 'events.jsonl') as audit:
        controller = Controller(policy, audit, approvals=BrokenApprovals())
        with pytest.raises(ApprovalUnavailable):
            controller.submit(proposal(), execute=True, interactive=True, approval_reference='a' * 48)
        with pytest.raises(ApprovalUnavailable):
            controller.submit(proposal())


@pytest.mark.parametrize('execute', [False, True])
def test_cli_dry_run_and_noninteractive_execution_never_start_approval_worker(
    tmp_path, monkeypatch, capsys, execute,
):
    from recon_cockpit.secure_agent.coordinator_isolation import LinuxCoordinator

    def run(self, initial, exchange, *, control):
        initial = json.loads(initial)
        exchange(json.dumps({**initial, 'sequence': 1, 'plan': {
            'schema_version': '1', 'action': proposal(), 'done': True}}).encode(), control=control)
        return json.dumps({**initial, 'status': 'closed'}).encode()

    monkeypatch.setattr(LinuxCoordinator, 'run', run)
    monkeypatch.setattr(LinuxApprovalService, '_start', lambda *_: pytest.fail('must not start'))
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: False)
    monkeypatch.setattr(cli.sys.stdout, 'isatty', lambda: False)
    status = cli.main(['--control-plane-mock', 'three_step', '--isolated-approvals',
                      '--audit', str(tmp_path / 'audit.jsonl'), '--execute' if execute else '--dry-run'])
    assert status == (2 if execute else 0)
    summary = json.loads(capsys.readouterr().out)
    assert summary['actions_succeeded'] == 0
    if execute:
        assert summary['steps'][0]['reasons'] == ['noninteractive_approval_required']
    else:
        assert summary['steps'][0]['execution_status'] == 'dry_run'
