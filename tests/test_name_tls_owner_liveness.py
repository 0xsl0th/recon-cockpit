"""Portable verification of the native harness's process-pinning decisions."""

from copy import deepcopy
from pathlib import Path

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
    monkeypatch.setattr(observed.os, 'pidfd_open', open_pid)
    monkeypatch.setattr(observed.os, 'close', state['closed'].append)
    class Poll:
        def register(self, descriptor, flags):
            assert descriptor == 77 and flags == observed.select.POLLIN
        def poll(self, timeout):
            return [(77, observed.select.POLLIN | observed.select.POLLHUP)] if state['ready'] else []
    monkeypatch.setattr(observed.select, 'poll', Poll)
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
