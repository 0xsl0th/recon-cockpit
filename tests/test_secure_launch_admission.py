"""Pure authorization state and trusted wrapper mechanics; no OS isolation claims."""

from dataclasses import asdict, replace
import json
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import launch_admission as protocol, cli
from recon_cockpit.secure_agent.admission_isolation import LinuxLaunchAdmission
from recon_cockpit.secure_agent.admitted_execution import AdmissionGatedBackend
from recon_cockpit.secure_agent.authorized_execution import AuthorizedFixtureBackend
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.planner import proposal
from recon_cockpit.secure_agent.session import SessionLimits
from scripts.secure_agent_control_plane_demo import demo_policy


def initial(**changes):
    return {'configuration': {'version': '1', 'service_id': str(uuid4()), 'session_id': str(uuid4()),
        'policy': demo_policy().to_dict(), 'limits': asdict(SessionLimits()), 'execute': True,
        'profile': 'fixture', 'case': None, **changes}, 'deadline': 130.0}


def request(state, operation='admit', *, chosen=None, policy_digest=None, permit=None, **changes):
    value = {'version': '1', 'service_id': state.config['service_id'], 'session_id': state.config['session_id'],
        'sequence': state._sequence, 'operation': operation,
        'action': proposal() if chosen is None else chosen.to_dict(),
        'policy_digest': demo_policy().digest if policy_digest is None else policy_digest}
    if operation == 'redeem':
        value['permit'] = permit
    return {**value, **changes}


def state(**changes):
    return protocol.AdmissionState(initial(**changes), clock=lambda: 100.0)


def test_one_use_permit_owns_reservation_without_refund():
    authority = state()
    admitted = authority.handle(request(authority))
    assert admitted['reason'] is None and len(admitted['permit']) == 64
    assert admitted['snapshot'] == {'executions_reserved': 1, 'output_bytes_reserved': 1024}


@pytest.mark.parametrize('change,reason', [('action', 'admission_action_changed'),
    ('policy', 'admission_policy_changed'), ('expiry', 'admission_expired'),
    ('none', 'admission_missing'), ('unknown', 'admission_unknown_or_replayed')])
def test_permit_binding_expiry_and_burn(change, reason):
    now = [100.0]
    authority = protocol.AdmissionState(initial(limits=asdict(SessionLimits(max_output_bytes=8192))),
                                        clock=lambda: now[0])
    admitted = authority.handle(request(authority))
    permit = admitted['permit']
    assert permit
    chosen = parse_action(proposal())
    if change == 'action':
        chosen = replace(chosen, rationale='changed after admission')
    if change == 'expiry':
        now[0] = 105.0
    received = None if change == 'none' else 'f' * 64 if change == 'unknown' else permit
    result = authority.handle(request(authority, 'redeem', permit=received, chosen=chosen,
                                       policy_digest='a' * 64 if change == 'policy' else None))
    assert result['reason'] == reason
    if change not in ('none', 'unknown'):
        assert authority.handle(request(authority, 'redeem', permit=permit))['reason'] == 'admission_unknown_or_replayed'
    assert result['snapshot'] == admitted['snapshot']


def test_valid_redemption_and_replay_keep_counters():
    authority = state(limits=asdict(SessionLimits(max_output_bytes=8192)))
    admitted = authority.handle(request(authority))
    for expected in (None, 'admission_unknown_or_replayed'):
        result = authority.handle(request(authority, 'redeem', permit=admitted['permit']))
        assert result['permit'] is None and result['reason'] == expected
        assert result['snapshot'] == admitted['snapshot']


@pytest.mark.parametrize('change', [
    {'version': 1}, {'execute': 1}, {'profile': 'routed'}, {'profile': []},
    {'case': 'a'}, {'profile': 'owned_lab', 'case': ''}, {'profile': 'owned_lab', 'case': 'ab'},
    {'profile': 'owned_lab', 'case': 'g'}, {'session_id': 'foreign'}, {'service_id': True},
    {'policy': {}}, {'limits': {}}, {'approved': True}, {'command': 'id'},
])
def test_invalid_bootstrap_configuration(change):
    with pytest.raises(ValueError):
        state(**change)


@pytest.mark.parametrize('change', [
    {'operation': 'reset'}, {'operation': 'configure'}, {'operation': []}, {'approved': True},
    {'audit_acknowledged': True}, {'sequence': True}, {'sequence': 2}, {'sequence': 0},
    {'service_id': str(uuid4())}, {'session_id': str(uuid4())}, {'policy_digest': 'x' * 64},
    {'action': {}}, {'permit': 'a' * 64}, {'output_reserved_before': 0},
])
def test_forged_requests_cannot_admit(change):
    authority = state()
    with pytest.raises(ValueError):
        authority.handle({**request(authority), **change})
    assert authority._steps == authority._output == 0


@pytest.mark.parametrize('raw', [b'[]', b'{"x":1,"x":2}', b'{"x":NaN}', b'{}{}', b'x' * 32769, '{}'])
def test_malformed_wire(raw):
    with pytest.raises(ValueError):
        protocol.decode(raw)


@pytest.mark.parametrize('deadline', [100.0, 161.0, True, float('nan'), float('inf'), '130'])
def test_invalid_or_extended_deadline(deadline):
    with pytest.raises(ValueError):
        protocol.AdmissionState({**initial(), 'deadline': deadline}, clock=lambda: 100.0)


@pytest.mark.parametrize('field,value', [('max_steps', 0), ('max_steps', 17), ('max_steps', True),
    ('max_runtime_seconds', 601), ('max_output_bytes', 1048577), ('max_output_bytes', -1)])
def test_independent_limit_ceilings(field, value):
    with pytest.raises(ValueError):
        state(limits={**asdict(SessionLimits()), field: value})


@pytest.mark.parametrize('mode,reason', [('dry', 'admission_dry_run'), ('policy', 'admission_policy_changed'),
    ('deny', 'admission_policy_denied'), ('profile', 'admission_profile_denied'),
    ('steps', 'admission_step_limit'), ('output', 'admission_output_limit')])
def test_admission_denial_preserves_reservations(mode, reason):
    config = initial(execute=mode != 'dry', limits=asdict(SessionLimits(max_steps=1, max_output_bytes=8192)))
    authority = protocol.AdmissionState(config, clock=lambda: 100.0)
    chosen = parse_action(proposal())
    if mode == 'deny':
        chosen = replace(chosen, target='192.0.2.1')
    if mode == 'profile':
        raw = demo_policy().to_dict()
        raw['allowed_targets'] = ['127.0.0.0/8']
        authority = state(policy=raw)
        chosen = replace(chosen, target='127.0.0.2')
    if mode == 'steps':
        assert authority.handle(request(authority))['permit']
    if mode == 'output':
        authority = state(limits=asdict(SessionLimits(max_output_bytes=1)))
    before = (authority._steps, authority._output)
    outcome = authority.handle(request(authority, chosen=chosen,
        policy_digest='a' * 64 if mode == 'policy' else authority._policy.digest))
    assert outcome['reason'] == reason and outcome['permit'] is None
    assert (authority._steps, authority._output) == before


def test_boundaries_expire_and_no_request_can_extend_session():
    now = [100.0]
    authority = protocol.AdmissionState(initial(limits=asdict(SessionLimits(max_output_bytes=8192))),
                                        clock=lambda: now[0])
    permit = authority.handle(request(authority))['permit']
    now[0] = 130.0
    with pytest.raises(ValueError, match='expired'):
        authority.handle(request(authority, 'redeem', permit=permit))


def test_recreated_worker_and_foreign_session_cannot_redeem_old_permit():
    authority = state(limits=asdict(SessionLimits(max_output_bytes=8192)))
    permit = authority.handle(request(authority))['permit']
    restarted = protocol.AdmissionState({'configuration': authority.config, 'deadline': 130}, clock=lambda: 100)
    assert restarted.handle(request(restarted, 'redeem', permit=permit))['reason'] == 'admission_unknown_or_replayed'
    with pytest.raises(ValueError):
        authority.handle(request(authority, 'redeem', permit=permit, session_id=str(uuid4())))


def test_configuration_cloned_and_request_ceiling_is_independent():
    init = initial(limits=asdict(SessionLimits(max_output_bytes=8192)))
    authority = protocol.AdmissionState(init, clock=lambda: 100)
    init['configuration']['execute'] = False
    init['configuration']['limits']['max_steps'] = 16
    assert authority.handle(request(authority))['permit']
    assert authority.config['limits']['max_steps'] == 3
    authority._sequence = 33
    with pytest.raises(ValueError):
        authority.handle(request(authority))


@pytest.mark.parametrize('change', [
    {'permit': None}, {'permit': True}, {'reason': 'arbitrary'}, {'extra': True},
    {'snapshot': {'executions_reserved': True, 'output_bytes_reserved': 1}},
    {'snapshot': {'executions_reserved': 4, 'output_bytes_reserved': 1}},
    {'snapshot': {'executions_reserved': 1, 'output_bytes_reserved': 10000000}},
])
def test_bad_receipt_result(change):
    authority = state()
    value = {'permit': 'b' * 64, 'reason': None, 'snapshot': {'executions_reserved': 1, 'output_bytes_reserved': 1024},
             **change}
    with pytest.raises(ValueError):
        protocol.result(value, 'admit', authority.config)


def test_service_constructor_and_unissued_redemption_cannot_start(monkeypatch):
    with LinuxLaunchAdmission(demo_policy(), str(uuid4()), SessionLimits(), execute=True) as service:
        starts = []
        monkeypatch.setattr(service, '_start', lambda *_: starts.append(True))
        with pytest.raises(IsolationUnavailable):
            service.redeem('b' * 64, parse_action(proposal()), demo_policy(), control=ExecutionControl(time.monotonic()+10))
        assert starts == [] and service._closed


@pytest.mark.parametrize('change', [
    {'sequence': 0}, {'session_id': str(uuid4())}, {'request_digest': '0' * 64}, {'extra': True},
])
def test_bad_reply_poisoning_without_retry(monkeypatch, change):
    service = LinuxLaunchAdmission(demo_policy(), str(uuid4()), SessionLimits(max_output_bytes=8192), execute=True)
    control = ExecutionControl(time.monotonic()+10)
    service._control = control
    service._supervisor = SimpleNamespace(deadline=control.deadline, close=lambda: None)
    sent = []
    monkeypatch.setattr(service, '_quiet', lambda: None)
    monkeypatch.setattr(service, '_send', lambda raw: sent.append(protocol.decode(raw)))
    outcome = {'permit': 'b' * 64, 'reason': None, 'snapshot': {'executions_reserved': 1, 'output_bytes_reserved': 1024}}
    monkeypatch.setattr(service, '_reply', lambda: {**protocol.receipt(sent[-1], outcome), **change})
    with pytest.raises(IsolationUnavailable):
        service.admit(parse_action(proposal()), demo_policy(), control=control)
    with pytest.raises(IsolationUnavailable):
        service.admit(parse_action(proposal()), demo_policy(), control=control)
    assert len(sent) == 1 and service._closed


@pytest.mark.parametrize('source', [[], ['--mock'], ['--session-mock', 'three_step'],
    ['--control-plane-mock', 'three_step'], ['--control-plane-mock', 'three_step', '--isolated-audit'],
    ['--control-plane-mock', 'three_step', '--isolated-approvals'], ['--evaluate-owned-lab'],
    ['--inspect-assessment', '/missing']])
def test_cli_rejects_incomplete_or_unsupported_selection_before_io(monkeypatch, source):
    reads = []
    monkeypatch.setattr(cli, '_read_bounded', lambda *_: reads.append(True))
    with pytest.raises(SystemExit) as error:
        cli.main([*source, '--isolated-launch-admission'])
    assert error.value.code == 2 and reads == []


@pytest.mark.parametrize('failure', ['admit', 'redeem', 'bad_permit', 'cancel', 'backend'])
def test_gate_never_launches_without_successful_admission_and_redemption(monkeypatch, failure):
    policy = demo_policy()
    underlying = AuthorizedFixtureBackend(policy, str(uuid4()), SessionLimits(), execute=True)
    gate = AdmissionGatedBackend(underlying)
    control = ExecutionControl(time.monotonic()+10)
    calls = []
    def admit(*_a, **_k):
        calls.append('admit')
        if failure == 'admit':
            raise IsolationUnavailable()
        return {'permit': 'a' * 64, 'reason': None}
    def redeem(*_a, **_k):
        calls.append('redeem')
        if failure == 'redeem':
            raise IsolationUnavailable()
        if failure == 'cancel':
            raise ExecutionStopped('session_cancelled')
        return {'reason': 'admission_unknown_or_replayed' if failure == 'bad_permit' else None}
    def run(*_a, **_k):
        calls.append('launch')
        raise RuntimeError('OWNED-FAILURE')
    monkeypatch.setattr(gate._admission, 'admit', admit)
    monkeypatch.setattr(gate._admission, 'redeem', redeem)
    monkeypatch.setattr(underlying, 'run', run)
    with pytest.raises(RuntimeError):
        gate.run(parse_action(proposal()), policy, control=control)
    assert ('launch' in calls) == (failure == 'backend')
    with pytest.raises(IsolationUnavailable):
        gate.run(parse_action(proposal()), policy, control=control)
    assert gate._admission._closed and gate._stopped.is_set()


@pytest.mark.parametrize('profile,tool,target,port,path,allowed', [
    ('fixture', 'http_probe', '127.0.0.1', 8080, '/', True),
    ('fixture', 'tcp_connect', '127.0.0.1', 8080, '/', False),
    ('fixture', 'http_probe', '127.0.0.2', 8080, '/', False),
    ('fixture', 'http_probe', '127.0.0.0/30', 8080, '/', False),
    ('fixture', 'http_probe', '127.0.0.1', 80, '/', False),
    ('discovery_fixture', 'tcp_connect', '127.0.0.1', 8080, '/', True),
    ('discovery_fixture', 'http_probe', '127.0.0.1', 8081, '/', False),
    ('owned_lab', 'http_probe', '127.0.0.1', 8080, '/assessment/a/index.json', True),
    ('owned_lab', 'http_probe', '127.0.0.1', 8080, '/assessment/b/index.json', False),
    ('owned_lab', 'http_probe', '127.0.0.1', 8080, '/', False),
])
def test_independent_fixture_profile_does_not_expand(profile, tool, target, port, path, allowed):
    raw = proposal()
    raw.update(tool_id=tool, target=target)
    raw['parameters'] = {'port': port, 'timeout_seconds': 1, 'max_output_bytes': 1024}
    if tool == 'http_probe':
        raw['parameters'].update(method='GET', path=path)
    config = initial(profile=profile, case='a' if profile == 'owned_lab' else None)['configuration']
    assert protocol.profile_allows(parse_action(raw), config) is allowed


def test_dry_mode_cannot_start_a_worker_or_be_upgraded(monkeypatch):
    from recon_cockpit.secure_agent.planner_isolation import LinuxIsolatedMockProvider
    probes = []
    monkeypatch.setattr(LinuxIsolatedMockProvider, 'check_available', lambda *_: probes.append(True))
    with LinuxLaunchAdmission(demo_policy(), str(uuid4()), SessionLimits(), execute=False) as service:
        with pytest.raises(IsolationUnavailable):
            service.admit(parse_action(proposal()), demo_policy(), control=ExecutionControl(time.monotonic()+10))
        assert probes == [] and service._closed


@pytest.mark.parametrize('change', ['renewed_control', 'sequence', 'counter'])
def test_client_rejects_renewal_exhaustion_or_counter_rollback(monkeypatch, change):
    control = ExecutionControl(time.monotonic()+10)
    with LinuxLaunchAdmission(demo_policy(), str(uuid4()), SessionLimits(), execute=True) as service:
        service._control = control
        service._supervisor = SimpleNamespace(deadline=control.deadline, close=lambda: None)
        if change == 'sequence':
            service._sequence = 32
        sent = []
        monkeypatch.setattr(service, '_quiet', lambda: None)
        monkeypatch.setattr(service, '_send', lambda raw: sent.append(protocol.decode(raw)))
        outcome = {'permit': 'a' * 64, 'reason': None, 'snapshot': {'executions_reserved': 0, 'output_bytes_reserved': 0}}
        monkeypatch.setattr(service, '_reply', lambda: protocol.receipt(sent[-1], outcome))
        with pytest.raises(IsolationUnavailable):
            service.admit(parse_action(proposal()), demo_policy(),
                          control=replace(control) if change == 'renewed_control' else control)
        assert len(sent) == (1 if change == 'counter' else 0)
        assert service._closed


def test_cancellation_after_redemption_cannot_launch(monkeypatch):
    import threading
    stopped = threading.Event()
    control = ExecutionControl(time.monotonic()+10, stopped)
    policy = demo_policy()
    backend = AuthorizedFixtureBackend(policy, str(uuid4()), SessionLimits(), execute=True)
    launches = []
    with AdmissionGatedBackend(backend) as gate:
        monkeypatch.setattr(gate._admission, 'admit', lambda *_a, **_k: {'permit': 'a'*64, 'reason': None})
        def redeem(*_a, **_k):
            stopped.set()
            return {'reason': None}
        monkeypatch.setattr(gate._admission, 'redeem', redeem)
        monkeypatch.setattr(backend, 'run', lambda *_a, **_k: launches.append(True))
        with pytest.raises(ExecutionStopped, match='session_cancelled'):
            gate.run(parse_action(proposal()), policy, control=control)
    assert launches == []


def test_concurrent_attempt_poisons_inflight_redemption_before_launch(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    entered, release = threading.Event(), threading.Event()
    control = ExecutionControl(time.monotonic()+10)
    policy = demo_policy()
    backend = AuthorizedFixtureBackend(policy, str(uuid4()), SessionLimits(), execute=True)
    launches = []
    with AdmissionGatedBackend(backend) as gate, ThreadPoolExecutor(max_workers=1) as pool:
        monkeypatch.setattr(gate._admission, 'admit', lambda *_a, **_k: {'permit': 'a'*64, 'reason': None})
        def redeem(*_a, **_k):
            entered.set()
            assert release.wait(2)
            return {'reason': None}
        monkeypatch.setattr(gate._admission, 'redeem', redeem)
        monkeypatch.setattr(backend, 'run', lambda *_a, **_k: launches.append(True))
        pending = pool.submit(gate.run, parse_action(proposal()), policy, control=control)
        try:
            assert entered.wait(2)
            with pytest.raises(IsolationUnavailable, match='already running'):
                gate.run(parse_action(proposal()), policy, control=control)
        finally:
            release.set()
        with pytest.raises(IsolationUnavailable, match='closed'):
            pending.result(timeout=2)
    assert launches == []


@pytest.mark.parametrize('execute', [False, True])
def test_cli_dry_or_noninteractive_modes_do_not_start_admission(tmp_path, monkeypatch, capsys, execute):
    from recon_cockpit.secure_agent import audit_isolation
    from recon_cockpit.secure_agent.audit import AuditSink
    from recon_cockpit.secure_agent.coordinator_isolation import LinuxCoordinator
    def run(self, initial, exchange, *, control):
        initial = json.loads(initial)
        exchange(json.dumps({**initial, 'sequence': 1, 'plan': {
            'schema_version': '1', 'action': proposal(), 'done': True}}).encode(), control=control)
        return json.dumps({**initial, 'status': 'closed'}).encode()
    monkeypatch.setattr(LinuxCoordinator, 'run', run)
    monkeypatch.setattr(audit_isolation, 'LinuxAuditSink', AuditSink)
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: False)
    monkeypatch.setattr(cli.sys.stdout, 'isatty', lambda: False)
    calls = []
    monkeypatch.setattr(LinuxLaunchAdmission, 'admit', lambda *_a, **_k: calls.append(True))
    status = cli.main(['--control-plane-mock', 'three_step', '--fixture', '--isolated-approvals',
        '--isolated-audit', '--isolated-launch-admission', '--audit', str(tmp_path/'events.jsonl'),
        '--execute' if execute else '--dry-run'])
    assert status == (2 if execute else 0) and calls == []
    summary = json.loads(capsys.readouterr().out)
    assert summary['actions_succeeded'] == 0 and summary['live_calls_enabled'] is False
