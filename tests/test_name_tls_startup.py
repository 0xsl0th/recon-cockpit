"""One shared ARM-to-release startup budget; simulated orchestration only."""

from types import SimpleNamespace
import threading

import pytest

from recon_cockpit.secure_agent import name_tls_services as services
from recon_cockpit.secure_agent import name_tls_contract as contract
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.routed import _BudgetExceeded
from test_name_tls_authority import Harness
from test_name_tls_native_runtime import prepared, bundle


def owner(monkeypatch, *, deadline=160, case='O4'):
    clock = [100.0]
    monkeypatch.setattr(services.time, 'monotonic', lambda: clock[0])
    h = Harness(case)
    value = services.Services.__new__(services.Services)
    value.control = ExecutionControl(deadline, clock=services.time.monotonic)
    value.selection, value.identity = h.selected, h.identity
    value.runtime = bundle(prepared('A', case))
    value._check = value.control.check
    value._started, value.active, value.current_daemon = True, None, None
    supervisor = SimpleNamespace(deadline=deadline, control=value.control)
    supervisor.check = lambda: services._Supervisor.check(supervisor)
    supervisor.processes = {}
    def poll(timeout):
        clock[0] += timeout
        return []
    supervisor.selector = SimpleNamespace(select=poll)
    supervisor.wait_for = lambda predicate: services._Supervisor.wait_for(supervisor, predicate)
    value.topology = SimpleNamespace(ledger_request=lambda message: {'status': 'ok'},
        namespace_fds=lambda role: (13, 14), namespaces=lambda role: {}, _supervisor=supervisor)
    return value, parse_action(contract.dns_action(h.selected, h.identity)), clock


@pytest.mark.parametrize('owner_deadline,expected', ((160, 102), (101.5, 101.5)))
def test_arm_roundtrip_consumes_shared_startup_instead_of_restarting_it(monkeypatch, owner_deadline, expected):
    value, action, clock = owner(monkeypatch, deadline=owner_deadline)
    def arm(message):
        clock[0] += .75
        return {'status': 'ok'}
    value.topology.ledger_request = arm
    assert value.arm_action(action, 1) == {'status': 'ok'}
    assert value.active['started'] == 100
    assert value.active['startup_deadline'] == expected
    view = services._ActionView(value, {})
    assert view.startup_deadline == expected
    assert view.deadline == min(110, owner_deadline)


@pytest.mark.parametrize('operation', ('prepare', 'arm'))
def test_recorder_preparation_and_release_cannot_wait_past_shared_startup(monkeypatch, operation):
    value, action, clock = owner(monkeypatch)
    value.arm_action(action, 1)
    supervisor = services._Supervisor(60, 16384, control=value.control)
    frontend = {'sequence': 0, 'supervisor': supervisor, 'channel': object()}
    sent = []
    def send(current, channel, message, descriptor=None):
        assert current.control is value.control and current.deadline == 102
        current.check()
        sent.append(message)
    def receive(current, channel):
        clock[0] = 102
        current.check()
        pytest.fail('expired startup must not accept a recorder reply')
    monkeypatch.setattr(services, '_send', send)
    monkeypatch.setattr(services, '_receive', receive)
    try:
        with pytest.raises(_BudgetExceeded):
            value._command(frontend, operation)
        assert len(sent) == 1 and supervisor.deadline == 160
        assert value.control.remaining() > 0
    finally:
        supervisor.close()


def test_finished_recorder_uses_whole_action_budget_after_startup(monkeypatch):
    value, action, clock = owner(monkeypatch)
    value.arm_action(action, 1)
    clock[0] = 105
    supervisor = services._Supervisor(55, 16384, control=value.control)
    frontend = {'sequence': 0, 'supervisor': supervisor, 'channel': object()}
    reply = {'sequence': 1, 'operation': 'finish', 'recorder': {}, 'raw_streams': {}, 'reservations': [],
             'budget_denied': False, 'last_budget_reply': None, 'descriptor_custody': {}}
    def send(current, channel, message, descriptor=None):
        assert current.deadline == 110
        current.check()
    monkeypatch.setattr(services, '_send', send)
    monkeypatch.setattr(services, '_receive', lambda current, channel: (reply, None))
    try:
        assert value._command(frontend, 'finish') == reply
    finally:
        supervisor.close()


@pytest.mark.parametrize('phase', ('native', 'source'))
def test_daemon_staging_uses_remaining_shared_budget_and_cleans_up(monkeypatch, phase):
    value, action, clock = owner(monkeypatch)
    value.arm_action(action, 1)
    clock[0] = 101.5
    controls, channels, supervisors = [], [], []
    class Channel:
        def __init__(self):
            self.closed = False
            channels.append(self)
        def setblocking(self, blocking):
            pass
        def close(self):
            self.closed = True
    class Supervisor(services._Supervisor):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.closed = False
            supervisors.append(self)
        def launch(self, *args, **kwargs):
            pytest.fail('expired staging must not launch a daemon')
        def close(self):
            super().close()
            self.closed = True
    def staging(supplied, current):
        controls.append(supplied)
        assert supplied.deadline == 102 and supplied is not value.control
        if phase == current:
            clock[0] = 102
        supplied.check()
    def native_stage(manifest, unused1, unused2, supplied, **kwargs):
        staging(supplied, 'native')
        return []
    def source_stage(runtime, modules, supplied):
        staging(supplied, 'source')
        return {}
    monkeypatch.setattr(services.socket, 'socketpair', lambda *args: (Channel(), Channel()))
    monkeypatch.setattr(services, '_Supervisor', Supervisor)
    monkeypatch.setattr(services, 'sealed_snapshots', native_stage)
    monkeypatch.setattr(services.sources, 'snapshot_sources', source_stage)
    with pytest.raises(IsolationUnavailable, match='Name/TLS daemon: session_timeout'):
        value._daemon('dns')
    assert supervisors[0].closed and supervisors[0].control is value.control
    assert all(channel.closed for channel in channels)
    assert value.current_daemon is None and value.control.remaining() > 0
    assert controls


@pytest.mark.parametrize('mode', ('poll', 'late_return', 'error'))
def test_arm_rpc_clips_existing_supervisor_and_restores_deadline(monkeypatch, mode):
    value, action, clock = owner(monkeypatch)
    supervisor = value.topology._supervisor
    observed = []
    def arm(message):
        observed.append((supervisor.deadline, supervisor.control))
        if mode == 'error':
            raise ValueError('simulated RPC failure')
        if mode == 'poll':
            supervisor.wait_for(lambda: False)
        clock[0] = 102
        return {'status': 'ok'}
    value.topology.ledger_request = arm
    with pytest.raises(ValueError if mode == 'error' else _BudgetExceeded):
        value.arm_action(action, 1)
    assert observed == [(102, value.control)]
    assert supervisor.deadline == 160 and supervisor.control is value.control
    assert value.active is None


def test_arm_rpc_preserves_an_already_shorter_topology_deadline(monkeypatch):
    value, action, clock = owner(monkeypatch)
    supervisor = value.topology._supervisor
    supervisor.deadline = 101
    def arm(message):
        assert supervisor.deadline == 101
        supervisor.wait_for(lambda: False)
    value.topology.ledger_request = arm
    with pytest.raises(_BudgetExceeded):
        value.arm_action(action, 1)
    assert supervisor.deadline == 101 and supervisor.control is value.control


@pytest.mark.parametrize('mode', ('poll', 'late_return'))
def test_preclient_binding_rpc_expires_before_client_launch_and_restores_owner(monkeypatch, mode):
    value, action, clock = owner(monkeypatch)
    value.arm_action(action, 1)
    supervisor = value.topology._supervisor
    value._lock = threading.Lock()
    value.frontends = {'dns': {}}
    value._daemon = lambda operation: {'private_socket': object(), 'ready': {'descriptor': {}}}
    value._command = lambda *args, **kwargs: None
    closed = []
    value._close_daemon = lambda: closed.append('daemon')
    value.close = lambda: closed.append('services')
    def snapshot():
        assert supervisor.deadline == 102 and supervisor.control is value.control
        if mode == 'poll':
            supervisor.wait_for(lambda: False)
        clock[0] = 102
        return {'binding': None}
    value.topology.ledger_snapshot = snapshot
    monkeypatch.setattr(services.client, 'run', lambda **kwargs: pytest.fail('expired binding RPC must not launch client'))
    with pytest.raises(_BudgetExceeded):
        value.run_action(action, {'sequence': 1, 'action_digest': action.digest})
    assert supervisor.deadline == 160 and supervisor.control is value.control
    assert closed == ['daemon', 'services'] and not value._lock.locked()


@pytest.mark.parametrize('phase', ('finish_action', 'final_snapshot'))
@pytest.mark.parametrize('mode', ('poll', 'late_return'))
def test_completion_rpc_stall_cannot_outlive_whole_action_or_publish_result(monkeypatch, phase, mode):
    from recon_cockpit.secure_agent import name_tls_parser
    value, action, clock = owner(monkeypatch)
    value.arm_action(action, 1)
    supervisor = value.topology._supervisor
    value._lock = threading.Lock()
    value.frontends = {'dns': {'ready': {}, 'mapping': {}}}
    value.closure = {}
    value.completed = []
    value._daemon = lambda operation: {'private_socket': object(), 'ready': {'descriptor': {}},
                                      'mapping': {}, 'native_ready': {}}
    finished = {'recorder': {'done': True, 'reason': 'complete', 'delivery_unknown': False},
        'budget_denied': False, 'raw_streams': {}, 'reservations': [], 'descriptor_custody': {}, 'last_budget_reply': None}
    value._command = lambda *args, **kwargs: finished
    closed = []
    value._close_daemon = lambda: closed.append('daemon')
    value.close = lambda: closed.append('services')
    snapshots = []
    def stall():
        assert supervisor.deadline == 110 and supervisor.control is value.control
        if mode == 'poll':
            supervisor.wait_for(lambda: False)
        clock[0] = 110
    def snapshot():
        snapshots.append(supervisor.deadline)
        if len(snapshots) == 2 and phase == 'final_snapshot':
            stall()
        return {'binding': None}
    def finish(message):
        assert message['operation'] == 'FINISH_ACTION'
        if phase == 'finish_action':
            stall()
        return {'status': 'ok'}
    value.topology.ledger_snapshot = snapshot
    value.topology.ledger_request = finish
    monkeypatch.setattr(services.client, 'run', lambda **kwargs: {'raw_output_base64': '', 'raw_stderr_base64': '',
        'provenance': {'exit_code': 0, 'stop_reason': None}, 'truncated': False, 'status': 'succeeded', 'bytes_received': 0})
    monkeypatch.setattr(name_tls_parser, 'encode_input', lambda *args, **kwargs: b'synthetic-frame')
    def parsed(*args, **kwargs):
        clock[0] = 109.5
        return {'useful_task_completed': True, 'expected_negative': False, 'observation': None}, {}, None
    monkeypatch.setattr(services, '_parse_completed_recording', parsed)
    with pytest.raises(_BudgetExceeded):
        value.run_action(action, {'sequence': 1, 'action_digest': action.digest})
    assert supervisor.deadline == 160 and supervisor.control is value.control
    assert snapshots == ([102] if phase == 'finish_action' else [102, 110])
    assert closed == ['daemon', 'daemon', 'services'] and not value._lock.locked()
    assert value.completed == []


def simulated_backend(monkeypatch, *, case='O4'):
    from recon_cockpit.secure_agent import name_tls_backend as backend
    monkeypatch.setattr(backend, '_namespaces', lambda: {
        name: name + ':[100]' for name in ('user', 'net', 'mnt', 'pid')})
    from recon_cockpit.secure_agent.name_tls_lab import NameTLSLab
    from recon_cockpit.secure_agent.session_limits import SessionLimits
    value, _, clock = owner(monkeypatch, case=case)
    policy = contract.policy_for_selection(value.selection, require_approval=False)
    limits = SessionLimits(**contract.limits(value.selection))
    lab = NameTLSLab(value.selection, value.identity['session_id'], limits,
                     execute=True, runtime=value.runtime)
    value.identity = lab.identity
    lab._control, lab.services, lab.topology = value.control, value, value.topology
    lab._started = True
    lab.start = lambda control: None
    closed = []
    lab.close = lambda: closed.append('lab')
    lab.topology.identity, lab.topology.parent_observation = {}, {}
    current = backend.ConfinedNameTLSBackend.__new__(backend.ConfinedNameTLSBackend)
    backend.AuthorizedNameTLSBackend.__init__(current, policy, lab.session_id, limits, lab, execute=True)
    current._closure = {'name_tls_runtime': value.runtime}
    current.check_available = lambda action: None
    return current, parse_action(contract.dns_action(value.selection, lab.identity)), clock, closed


@pytest.mark.parametrize('mode', ('success', 'poll', 'late_return', 'error'))
def test_backend_final_fresh_evidence_uses_retained_action_deadline_after_active_cleared(monkeypatch, mode):
    current, action, clock, closed = simulated_backend(monkeypatch)
    value = current.lab.services
    supervisor = value.topology._supervisor
    observed = []
    def evidence():
        observed.append((supervisor.deadline, supervisor.control))
        if len(observed) == 2:
            assert value.active is None
            if mode == 'poll':
                supervisor.wait_for(lambda: False)
            if mode == 'late_return':
                clock[0] = 110
            if mode == 'error':
                raise ValueError('simulated evidence RPC failure')
        return {'ledger': {'terminal': False, 'observation': len(observed)}, 'messages': []}
    def run(action, launch):
        assert value.active['deadline'] == 110
        clock[0] = 109.5
        value.active = None
        return {'status': 'succeeded', 'timing': {}}
    value.topology.ledger_evidence, value.run_action = evidence, run
    if mode == 'success':
        result = current.run(action, current._policy, control=value.control)
        assert result['name_tls_ledger']['observation'] == 2
        assert closed == []
    else:
        with pytest.raises(ValueError if mode == 'error' else _BudgetExceeded):
            current.run(action, current._policy, control=value.control)
        assert closed == ['lab']
        assert current.lab._last_ledger['observation'] == 1
    assert observed == [(160, value.control), (110, value.control)]
    assert supervisor.deadline == 160 and supervisor.control is value.control
    assert not current._lock.locked() and value.control.remaining() > 0


def test_nonadmitted_refusal_evidence_keeps_original_owner_budget(monkeypatch):
    current, action, clock, closed = simulated_backend(monkeypatch, case='N14')
    value = current.lab.services
    supervisor = value.topology._supervisor
    observed = []
    def evidence():
        observed.append((supervisor.deadline, supervisor.control))
        return {'ledger': {'terminal': False}, 'messages': []}
    value.topology.ledger_evidence = evidence
    value.topology.ledger_request = lambda message: {'status': 'denied', 'reason': 'binding_expired'}
    value.run_action = lambda *args: pytest.fail('refused ARM must not execute')
    result = current.run(action, current._policy, control=value.control)
    assert result['status'] == 'blocked' and result['name_tls_refusal']['source'] == 'owner_arm'
    assert observed == [(160, value.control), (160, value.control)]
    assert value.active is None and closed == [] and not current._lock.locked()
