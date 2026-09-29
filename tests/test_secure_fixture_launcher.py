"""Pure launcher contracts and host refusal mechanics; no OS isolation claims."""

from dataclasses import asdict, replace
import json
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import cli, launcher_protocol as protocol
from recon_cockpit.secure_agent.authorized_execution import AuthorizedFixtureBackend
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.planner import proposal
from recon_cockpit.secure_agent.session import SessionLimits
from scripts.secure_agent_control_plane_demo import demo_policy


def config(**changes):
    return {'version': '1', 'service_id': str(uuid4()), 'session_id': str(uuid4()),
        'policy': demo_policy().to_dict(), 'limits': asdict(SessionLimits()),
        'execute': True, 'profile': 'fixture', 'case': None, **changes}


def runtime():
    return {'stdlib': '/usr/lib/python3.13', 'files': ['/usr/bin/python3', '/usr/bin/bwrap', '/usr/sbin/nft',
            '/lib/x86_64-linux-gnu/libc.so.6', '/lib64/ld-linux-x86-64.so.2']}


def request(configuration, **changes):
    return {'version': '1', 'service_id': configuration['service_id'], 'session_id': configuration['session_id'],
        'sequence': 1, 'operation': 'execute', 'action': proposal(), 'policy_digest': demo_policy().digest, **changes}


def service(execute=True):
    return LinuxFixtureLauncher(AuthorizedFixtureBackend(demo_policy(), str(uuid4()), SessionLimits(), execute=execute))


def result():
    return {'backend': protocol.PROFILES['fixture'], 'status': 'succeeded', 'results': []}


@pytest.mark.parametrize('change', [
    {'profile': 'owned_lab', 'case': 'a'}, {'profile': 'routed'}, {'execute': 1},
    {'session_id': 'not-a-session'}, {'limits': {'max_steps': 100}}, {'command': 'id'},
    {'policy': {}}, {'case': 'a'},
])
def test_bootstrap_rejects_capability_expansion(change):
    with pytest.raises(ValueError):
        protocol.configuration(config(**change))


@pytest.mark.parametrize('change', [
    {'stdlib': '/home/private'}, {'stdlib': '/usr/lib/python3.13/../other'},
    {'files': ['/usr/bin/python3', '/usr/sbin/nft']},
    {'files': ['/usr/bin/python3', '/usr/sbin/nft', '/usr/bin/bwrap', '/bin/sh']},
    {'files': ['/usr/bin/python3', '/usr/sbin/nft', '/usr/bin/bwrap', '/lib/../private.so']},
    {'files': ['/usr/bin/python3', '/usr/sbin/nft', '/usr/bin/bwrap', '/usr/bin/bwrap']},
    {'files': [None]}, {'extra': True},
])
def test_runtime_closure_is_bounded_and_not_a_mount_api(change):
    with pytest.raises(ValueError):
        protocol.runtime({**runtime(), **change})


@pytest.mark.parametrize('deadline', [100, 161, True, float('nan'), float('inf'), '130'])
def test_original_deadline_is_fixed(deadline):
    with pytest.raises(ValueError):
        protocol.initial({'configuration': config(), 'runtime': runtime(), 'deadline': deadline}, 100)


@pytest.mark.parametrize('change', [
    {'operation': 'admit'}, {'operation': 'redeem'}, {'operation': 'reset'}, {'operation': 'shell'},
    {'approved': True}, {'audit_acknowledged': True}, {'permit': 'a'*64}, {'command': 'id'},
    {'limits': asdict(SessionLimits())}, {'output_reserved_before': 0}, {'deadline': 999},
    {'sequence': True}, {'sequence': 0}, {'sequence': 2}, {'session_id': str(uuid4())},
    {'service_id': str(uuid4())}, {'policy_digest': 'f'*64}, {'action': {}},
])
def test_requests_cannot_supply_launch_authority_or_reset_state(change):
    configuration = config()
    with pytest.raises(ValueError):
        protocol.request(request(configuration, **change), configuration, 1)


def test_valid_request_and_sequence_ceiling():
    configuration = config()
    assert protocol.request(request(configuration), configuration, 1).to_dict() == proposal()
    with pytest.raises(ValueError):
        protocol.request(request(configuration, sequence=4), configuration, 4)


@pytest.mark.parametrize('raw', [b'[]', b'{"x":1,"x":2}', b'{"x":NaN}', b'{}{}', b'{"x":"\xff"}',
                                  b'x'*(protocol.MAX_REPLY+1), '{}'])
def test_reply_json_is_strict_and_bounded(raw):
    with pytest.raises((ValueError, UnicodeError)):
        protocol.decode(raw)


def test_bounded_large_response_body_remains_data():
    value = {**result(), 'results': [{'body': '\u2603'*65536}]}
    assert protocol.decode(protocol.encode(value)) == value
    with pytest.raises(ValueError):
        protocol.encode({'body': 'x'*(protocol.MAX_REPLY+1)})


@pytest.mark.parametrize('change', [{'status': True}, {'status': 'approved'}, {'backend': 'shell'}, {'results': {}},
                                    {'status': None}, {'backend': None}])
def test_result_cannot_change_backend_or_status(change):
    with pytest.raises(ValueError):
        protocol.result({**result(), **change}, config())


def test_constructor_is_inert_and_dry_mode_cannot_upgrade(monkeypatch):
    with service(False) as launcher:
        calls = []
        monkeypatch.setattr(launcher, '_start', lambda *_: calls.append(True))
        with pytest.raises(IsolationUnavailable):
            launcher.run(parse_action(proposal()), demo_policy(), control=ExecutionControl(time.monotonic()+10))
        assert calls == [] and launcher._closed and launcher.boundary_checks is None


@pytest.mark.parametrize('change', ['sequence', 'snapshot', 'digest', 'result', 'extra', 'control'])
def test_host_rejects_forged_receipt_and_never_retries(monkeypatch, change):
    with service() as launcher:
        control = ExecutionControl(time.monotonic()+10)
        launcher._control = control
        launcher._supervisor = SimpleNamespace(deadline=control.deadline, close=lambda: None)
        monkeypatch.setattr(launcher, 'check_available', lambda *_: None)
        monkeypatch.setattr(launcher, '_quiet', lambda: None)
        sent = []
        monkeypatch.setattr(launcher, '_send', lambda raw: sent.append(json.loads(raw)))
        def reply():
            value = protocol.receipt(sent[-1], result(), {'executions_reserved': 1, 'output_bytes_reserved': 1024})
            if change == 'snapshot':
                value['snapshot']['executions_reserved'] = True
            else:
                value[{'sequence': 'sequence', 'digest': 'request_digest', 'result': 'result', 'extra': 'extra'}[change]] = None
            return value
        monkeypatch.setattr(launcher, '_reply', reply)
        with pytest.raises(IsolationUnavailable):
            launcher.run(parse_action(proposal()), demo_policy(), control=replace(control) if change == 'control' else control)
        assert launcher._closed and len(sent) == (0 if change == 'control' else 1)
        # Restore the real availability guard: a fault permanently closes it.
        monkeypatch.undo()
        with pytest.raises(IsolationUnavailable):
            launcher.run(parse_action(proposal()), demo_policy(), control=control)


@pytest.mark.parametrize('source', [[], ['--mock'], ['--control-plane-mock', 'three_step'],
    ['--control-plane-mock', 'three_step', '--fixture'],
    ['--control-plane-mock', 'three_step', '--isolated-audit', '--isolated-approvals', '--isolated-launch-admission'],
    ['--workflow-assessment', 'a', '--owned-lab', '--isolated-audit', '--isolated-approvals', '--isolated-launch-admission']])
def test_cli_incomplete_or_unsupported_modes_refuse_before_io(source, monkeypatch):
    reads = []
    monkeypatch.setattr(cli, '_read_bounded', lambda *_: reads.append(True))
    with pytest.raises(SystemExit) as exc:
        cli.main([*source, '--isolated-launcher'])
    assert exc.value.code == 2 and reads == []


def test_host_keeps_no_underlying_executor_handle():
    with service() as launcher:
        assert not hasattr(launcher, '_backend') and not hasattr(launcher, 'admit') and not hasattr(launcher, 'redeem')
        assert dict(launcher.snapshot) == {'executions_reserved': 0, 'output_bytes_reserved': 0}


@pytest.mark.parametrize('execute', [False, True])
def test_cli_dry_or_noninteractive_cannot_start_launcher(tmp_path, monkeypatch, capsys, execute):
    from recon_cockpit.secure_agent import audit_isolation
    from recon_cockpit.secure_agent.audit import AuditSink
    from recon_cockpit.secure_agent.coordinator_isolation import LinuxCoordinator
    def run(self, initial, exchange, *, control):
        initial = json.loads(initial)
        exchange(json.dumps({**initial, 'sequence': 1, 'plan': {'schema_version': '1', 'action': proposal(), 'done': True}}).encode(), control=control)
        return json.dumps({**initial, 'status': 'closed'}).encode()
    monkeypatch.setattr(LinuxCoordinator, 'run', run)
    monkeypatch.setattr(audit_isolation, 'LinuxAuditSink', AuditSink)
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: False)
    monkeypatch.setattr(cli.sys.stdout, 'isatty', lambda: False)
    starts = []
    monkeypatch.setattr(LinuxFixtureLauncher, '_start', lambda *_: starts.append(True))
    status = cli.main(['--control-plane-mock', 'three_step', '--fixture', '--isolated-audit', '--isolated-approvals',
        '--isolated-launch-admission', '--isolated-launcher', '--audit', str(tmp_path/'events.jsonl'),
        '--execute' if execute else '--dry-run'])
    assert status == (2 if execute else 0) and starts == []
    assert json.loads(capsys.readouterr().out)['live_calls_enabled'] is False
