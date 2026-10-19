"""Portable verification of the native harness's process-pinning decisions."""

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

import name_tls_owner_liveness as observed


IDENTITY = {'pid': 501, 'start_time_ticks': 12345,
            'namespaces': {name: name + ':[200]' for name in ('user', 'net', 'mnt', 'pid')}}


def fixtures(monkeypatch):
    state = {'ready': False, 'identity': deepcopy(IDENTITY), 'closed': [], 'opened': []}
    monkeypatch.setattr(observed, '_descendants', lambda _: {501})
    monkeypatch.setattr(observed, '_identity', lambda _: deepcopy(state['identity']))
    def open_pid(pid):
        state['opened'].append(pid)
        return 77
    monkeypatch.setattr(observed.os, 'pidfd_open', open_pid, raising=False)
    monkeypatch.setattr(observed.os, 'close', state['closed'].append)
    class Poll:
        def register(self, descriptor, flags):
            assert descriptor == 77 and flags == observed.select.POLLIN
        def poll(self, timeout):
            return [(77, observed.select.POLLIN | observed.select.POLLHUP)] if state['ready'] else []
    monkeypatch.setattr(observed.select, 'POLLIN', 1, raising=False)
    monkeypatch.setattr(observed.select, 'POLLHUP', 16, raising=False)
    monkeypatch.setattr(observed.select, 'poll', Poll, raising=False)
    host = {name: name + ':[100]' for name in ('user', 'net', 'mnt', 'pid')}
    monkeypatch.setattr(observed.os, 'readlink', lambda path: host[str(path).split('/')[-1]])
    return state


def test_same_pidfd_is_held_across_live_observations_and_closed_receipt_is_explicit(monkeypatch):
    state = fixtures(monkeypatch)
    pin = observed.OwnerPin(100, IDENTITY['namespaces'])
    before = pin.observe(alive=True)
    after = pin.observe(alive=True)
    assert before == after == {**IDENTITY, 'pidfd_readable': False, 'proc_absent': False, 'identity_source': 'current_proc'}
    assert state['opened'] == [501] and state['closed'] == []
    state['ready'] = True
    def no_proc_read(_):
        pytest.fail('reaped process identity must come from the retained pin')
    monkeypatch.setattr(observed, '_identity', no_proc_read)
    original_exists = Path.exists
    monkeypatch.setattr(Path, 'exists', lambda path: False if str(path) == '/proc/501' else original_exists(path))
    closed = pin.observe(alive=False)
    assert closed == {**IDENTITY, 'pidfd_readable': True, 'proc_absent': True, 'identity_source': 'retained_pin'}
    pin.close()
    pin.close()
    assert state['closed'] == [77]


@pytest.mark.parametrize('change', ('owner_death', 'start_time', 'namespace'))
def test_outer_launcher_survival_cannot_hide_owner_death_or_changed_identity(monkeypatch, change):
    state = fixtures(monkeypatch)
    pin = observed.OwnerPin(100, IDENTITY['namespaces'])
    if change == 'owner_death':
        state['ready'] = True
    elif change == 'start_time':
        state['identity']['start_time_ticks'] += 1
    else:
        state['identity']['namespaces']['net'] = 'net:[201]'
    with pytest.raises(AssertionError, match='actual topology owner'):
        pin.observe(alive=True)
    pin.close()
    assert state['closed'] == [77]


def test_namespace_mismatch_cannot_select_an_outer_launcher_or_different_owner(monkeypatch):
    state = fixtures(monkeypatch)
    different = dict(IDENTITY['namespaces'], net='net:[999]')
    with pytest.raises(AssertionError, match='not unique/live'):
        observed.OwnerPin(100, different)
    assert state['opened'] == state['closed'] == []


def test_identity_change_during_pidfd_pin_closes_the_candidate_descriptor(monkeypatch):
    state = fixtures(monkeypatch)
    values = iter((deepcopy(IDENTITY), {**IDENTITY, 'start_time_ticks': 67890}))
    monkeypatch.setattr(observed, '_identity', lambda _: next(values))
    with pytest.raises(AssertionError):
        observed.OwnerPin(100, IDENTITY['namespaces'])
    assert state['opened'] == [501] and state['closed'] == [77]


def test_approval_pin_selects_actual_fixed_python_payload_and_rechecks_it(monkeypatch):
    state = fixtures(monkeypatch)
    scripts = []
    def worker_identity(pid, script):
        scripts.append(script)
        return deepcopy(state['identity'])
    monkeypatch.setattr(observed, '_worker_identity', worker_identity)
    pin = observed.ApprovalPin(100)
    assert pin.observe(alive=True)['pid'] == 501
    assert scripts == [b'/app/approval_runtime/approval_worker.py'] * 3
    state['identity']['start_time_ticks'] += 1
    with pytest.raises(AssertionError, match='identity changed'):
        pin.observe(alive=True)
    pin.close()
    assert state['closed'] == [77]


def test_approval_pin_refuses_host_namespace_identity(monkeypatch):
    state = fixtures(monkeypatch)
    monkeypatch.setattr(observed, '_worker_identity', lambda *_: deepcopy(state['identity']))
    monkeypatch.setattr(observed.os, 'readlink', lambda path: state['identity']['namespaces'][str(path).split('/')[-1]])
    with pytest.raises(AssertionError, match='not unique/live'):
        observed.ApprovalPin(100)
    assert state['opened'] == state['closed'] == []


@pytest.mark.parametrize('change', (None, 'bootstrap', 'ancestry_race', 'supervisor_reuse'))
def test_approval_binding_observes_exact_bootstrap_and_rereads_live_chain(monkeypatch, change):
    from recon_cockpit.secure_agent import approval_protocol
    state = fixtures(monkeypatch)
    monkeypatch.setattr(observed, '_worker_identity', lambda *_: deepcopy(state['identity']))
    host = {name: name + ':[100]' for name in ('user', 'net', 'mnt', 'pid')}
    monkeypatch.setattr(observed.os, 'readlink', lambda path: host[str(path).split('/')[-1]])
    monkeypatch.setattr(observed.os, 'getpid', lambda: 50)
    initial = {'test_synthetic_bootstrap': True}
    argv = ['/usr/bin/python3', '-I', '-S', '/app/approval_runtime/approval_worker.py',
            approval_protocol.digest(initial), *(host[name] for name in ('user', 'net', 'mnt', 'pid')), 'launch-witness']
    if change == 'bootstrap':
        argv[4] = 'f' * 64
    raw = b'\0'.join(value.encode() for value in argv) + b'\0'
    monkeypatch.setattr(observed, '_read', lambda path: raw)
    calls = []
    def ancestry(pid):
        calls.append(pid)
        row = {'pid': pid, 'parent_pid': 100 if pid == 501 else 50,
               'start_time_ticks': IDENTITY['start_time_ticks'] if pid == 501 else 10000}
        if change == 'ancestry_race' and len(calls) > 2:
            row['start_time_ticks'] += 1
        return row
    monkeypatch.setattr(observed, '_ancestry_row', ancestry)
    pin = observed.ApprovalPin(100)
    try:
        if change:
            with pytest.raises(AssertionError):
                pin.binding(initial, SimpleNamespace(check=lambda: None), 9999 if change == 'supervisor_reuse' else 10000)
        else:
            value = pin.binding(initial, SimpleNamespace(check=lambda: None), 10000)
            assert value['bootstrap_sha256'] == approval_protocol.digest(initial)
            assert value['argv'] == argv and value['observer_pid'] == 50
            assert calls == [501, 100, 501, 100]
    finally:
        pin.close()
    assert state['closed'] == [77]
