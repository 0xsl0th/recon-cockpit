"""One shared ARM-to-release startup budget; simulated orchestration only."""

from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import name_tls_services as services
from recon_cockpit.secure_agent import name_tls_contract as contract
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.routed import _BudgetExceeded
from test_name_tls_authority import Harness
from test_name_tls_native_runtime import prepared, bundle


def owner(monkeypatch, *, deadline=160):
    clock = [100.0]
    monkeypatch.setattr(services.time, 'monotonic', lambda: clock[0])
    h = Harness()
    value = services.Services.__new__(services.Services)
    value.control = ExecutionControl(deadline, clock=services.time.monotonic)
    value.selection, value.identity = h.selected, h.identity
    value.runtime = bundle(prepared('A', 'O4'))
    value._check = value.control.check
    value._started, value.active, value.current_daemon = True, None, None
    value.topology = SimpleNamespace(ledger_request=lambda message: {'status': 'ok'},
        namespace_fds=lambda role: (13, 14), namespaces=lambda role: {})
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
