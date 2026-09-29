"""Owned launcher contracts; kernel enforcement is tested separately on Linux."""

from dataclasses import asdict
import json
from pathlib import Path
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import launcher_protocol as protocol, worker
from recon_cockpit.secure_agent.discovery_contract import discovery_action
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.owned_lab import OwnedLab, AuthorizedOwnedLabBackend
from recon_cockpit.secure_agent.owned_lab_contract import identity
from recon_cockpit.secure_agent.session import SessionLimits
from test_secure_fixture_launcher import runtime


def service(case='a', execute=True, **limits):
    policy = parse_policy(Path('examples/secure-agent-discovery-policy.json').read_text())
    session, limits = str(uuid4()), SessionLimits(**limits)
    lab = OwnedLab(case, session, limits, execute=execute)
    return LinuxFixtureLauncher(AuthorizedOwnedLabBackend(policy, session, limits, lab, execute=execute)), policy


@pytest.mark.parametrize('change', [
    {'owned_lab': None}, {'owned_lab': {}}, {'case': 'b'}, {'case': None},
    {'owned_lab': identity('b', str(uuid4()))}, {'namespace_fds': [4, 5]},
    {'profile': 'fixture'}, {'command': 'id'}, {'owned_lab': {'instance_id': 'invalid'}},
])
def test_owned_bootstrap_binds_exact_identity_and_case(change):
    launcher, _ = service()
    with pytest.raises(ValueError):
        protocol.configuration({**launcher._config, **change})


def test_owned_runtime_requires_nsenter_only_in_fixed_profile():
    launcher, _ = service()
    base = runtime()
    with pytest.raises(ValueError):
        protocol.initial({'configuration': launcher._config, 'runtime': base, 'deadline': 120}, 100)
    closure = {**base, 'files': [*base['files'], '/usr/bin/nsenter']}
    assert protocol.initial({'configuration': launcher._config, 'runtime': closure, 'deadline': 120}, 100) == launcher._config
    with pytest.raises(ValueError):
        protocol.runtime(closure)


@pytest.mark.parametrize('change', [
    {'namespace_fds': [4, 5]}, {'namespaces': {'net': 'net:[123]'}}, {'owned_lab': {}},
    {'connection_count': 0}, {'operation': 'close'}, {'operation': 'reset'},
    {'approved': True}, {'audit_acknowledged': True}, {'command': 'id'},
    {'action': discovery_action('b', 2)},
])
def test_owned_requests_cannot_choose_lab_or_namespace_or_reset_state(change):
    launcher, policy = service()
    config = launcher._config
    value = {'version': '1', 'service_id': config['service_id'], 'session_id': config['session_id'],
             'sequence': 1, 'operation': 'execute', 'action': discovery_action('a', 1), 'policy_digest': policy.digest}
    with pytest.raises(ValueError):
        protocol.request({**value, **change}, config, 1)


@pytest.mark.parametrize('fault', ['identity', 'connection', 'request', 'boolean', 'backend', 'missing', 'receipt', 'none'])
def test_host_validates_continuity_before_acknowledging_and_closes_without_retry(monkeypatch, fault):
    launcher, policy = service()
    control = ExecutionControl(time.monotonic()+20)
    launcher._control = control
    launcher._supervisor = SimpleNamespace(deadline=control.deadline, close=lambda: None)
    sent = []
    monkeypatch.setattr(launcher, 'check_available', lambda *_: None)
    monkeypatch.setattr(launcher, '_quiet', lambda: None)
    monkeypatch.setattr(launcher, '_send', lambda raw: sent.append(json.loads(raw)))
    def reply():
        context = {'identity': launcher.identity, 'connection_count': len(sent), 'request_count': len(sent)-1}
        result = {'backend': protocol.PROFILES['owned_lab'], 'status': 'succeeded', 'results': [], 'owned_lab': context}
        if len(sent) == 2:
            if fault == 'identity':
                context['identity'] = identity('a', str(uuid4()))
            if fault == 'connection':
                context['connection_count'] = 1
            if fault == 'request':
                context['request_count'] = 0
            if fault == 'boolean':
                context['connection_count'] = True
            if fault == 'backend':
                result['backend'] = protocol.PROFILES['fixture']
            if fault == 'missing':
                del result['owned_lab']
        receipt = protocol.receipt(sent[-1], result,
            {'executions_reserved': len(sent), 'output_bytes_reserved': len(sent)*1024})
        if len(sent) == 2 and fault == 'receipt':
            receipt['sequence'] = 99
        return receipt
    monkeypatch.setattr(launcher, '_reply', reply)
    first = launcher.run(parse_action(discovery_action('a', 1)), policy, control=control)
    first['owned_lab']['connection_count'] = 15  # Returned data cannot alter cached evidence.
    if fault == 'none':
        launcher.run(parse_action(discovery_action('a', 2)), policy, control=control)
    else:
        with pytest.raises(IsolationUnavailable):
            launcher.run(parse_action(discovery_action('a', 2)), policy, control=control)
        assert launcher._closed
    receipt = launcher.close()
    assert receipt['connection_count'] == (2 if fault == 'none' else 1)
    assert receipt['request_count'] == (1 if fault == 'none' else 0)
    receipt['identity']['instance_id'] = 'changed'
    assert launcher.close()['identity'] == launcher.identity and len(sent) == 2


def test_cleanup_failure_never_fabricates_closure():
    launcher, _ = service()
    def fail():
        raise IsolationUnavailable('owned cleanup failure')
    launcher._supervisor = SimpleNamespace(close=fail)
    with pytest.raises(IsolationUnavailable):
        launcher.close()
    with pytest.raises(IsolationUnavailable, match='cleanup was not verified'):
        launcher.close()
    assert launcher._lab_receipt is None


def test_owned_dry_client_is_metadata_only_and_cannot_upgrade(monkeypatch):
    launcher, policy = service(execute=False)
    monkeypatch.setattr(OwnedLab, 'start', lambda *_: pytest.fail('host lab started'))
    monkeypatch.setattr(launcher, '_start', lambda *_: pytest.fail('launcher started'))
    with pytest.raises(IsolationUnavailable):
        launcher.run(parse_action(discovery_action('a', 1)), policy, control=ExecutionControl(time.monotonic()+20))
    assert not hasattr(launcher, 'lab') and not hasattr(launcher, '_namespace_fds')
    assert launcher.close() == {'identity': launcher.identity, 'status': 'closed', 'connection_count': 0, 'request_count': 0}


@pytest.mark.parametrize('inherited', ['unlimited', 30, 600])
def test_child_limits_never_raise_inherited_hard_ceiling(monkeypatch, inherited):
    import resource
    inherited = resource.RLIM_INFINITY if inherited == 'unlimited' else inherited
    calls = {}
    monkeypatch.setattr(resource, 'getrlimit', lambda kind: (inherited, inherited))
    monkeypatch.setattr(resource, 'setrlimit', lambda kind, limits: calls.update({kind: limits}))
    worker._set_limits(60)
    assert calls[resource.RLIMIT_CPU] == ((30, 30) if inherited == 30 else (62, 62))
    assert all(soft == hard and (inherited == resource.RLIM_INFINITY or hard <= inherited) for soft, hard in calls.values())


def test_extracted_session_limits_preserves_public_type_and_digest():
    from recon_cockpit.secure_agent.session_limits import SessionLimits as Limits
    from recon_cockpit.secure_agent.launch_admission import digest
    assert SessionLimits is Limits and SessionLimits().digest == digest(asdict(Limits()))
