"""Synthetic host/ledger regressions; no native execution or isolation claims."""

from copy import deepcopy
import json
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import launcher_protocol as protocol
from recon_cockpit.secure_agent import name_tls_contract as contract, name_tls_public as public
from recon_cockpit.secure_agent import name_tls_context as context, name_tls_ledger as ledger
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from test_name_tls_authority import Harness
from test_name_tls_evidence import manifest
from test_name_tls_topology import metadata
from test_secure_fixture_launcher import service


def refusals(configuration='A'):
    chosen = manifest(configuration, 'N14', execute=True)
    h = Harness(case='N14', configuration=configuration)
    h.identity = chosen['identity']
    h.ledger = ledger.Ledger(h.selected, h.identity, started_at=0, clock=lambda: h.clock)
    h.dns()
    state = h.ledger.snapshot()
    topology = metadata(configuration)
    parent = {'namespaces': deepcopy(topology['owner_namespaces']), 'payload_pid': 1234,
              'mapping': {'launcher_uid': 1000, 'launcher_gid': 1000,
                          'uid_map': [[65534, 1000, 1]], 'gid_map': [[65534, 1000, 1]]}}
    previous = {'identity': h.identity, 'sequence': 1, 'connection_count': 1, 'request_count': 1,
        'binding': state['binding'], 'topology_sha256': public.digest(topology),
        'topology_parent_sha256': public.digest(parent), 'event_count': len(state['events']),
        'events_sha256': public.digest(state['events']), 'actions_sha256': public.digest(state['actions']),
        'message_count': len(h.messages), 'messages_sha256': public.digest(h.messages),
        'frontends': {'dns_frontend': 'a' * 64}}
    candidates = []
    for sequence, slot in ((2, 'http'), (3, 'tls')):
        before = {'ledger': h.ledger.snapshot(), 'messages': deepcopy(h.messages)}
        action = contract.service_action(h.selected, h.identity, slot, state['binding'])
        if slot == 'http':
            h.clock = 2.0
            assert h.arm(slot)['reason'] == 'binding_expired'
        candidates.append({'status': 'blocked', 'backend': contract.BACKEND, 'results': [],
            'tool_observation': None, 'bytes_received': 0, 'truncated': False,
            'name_tls_refusal': {'action': action, 'execution_sequence': sequence,
                'source': 'owner_arm' if slot == 'http' else 'owner_terminal',
                'reason': 'binding_expired', 'before': before},
            'name_tls_ledger': h.ledger.snapshot(), 'name_tls_messages': deepcopy(h.messages),
            'name_tls_topology': topology, 'name_tls_topology_parent_observation': parent,
            'owned_lab': {'identity': h.identity}, 'timing': {'owner_and_action_elapsed_ms': 0}})
    return chosen, previous, candidates


def host(monkeypatch, chosen, previous, candidates):
    launcher = service()
    launcher._config = protocol.configuration({**launcher._config, 'profile': contract.PROFILE,
        'case': chosen['selection'], 'session_id': chosen['session_id'], 'policy': chosen['policy'],
        'limits': chosen['limits'], 'owned_lab': chosen['identity']})
    launcher._name_tls_runtime = chosen['runtime']
    launcher._sequence = 1
    launcher._snapshot = {'executions_reserved': 1, 'output_bytes_reserved': contract.action_bounds('dns_1')['output_bytes']}
    launcher._lab_context = previous
    control = ExecutionControl(time.monotonic() + 10)
    launcher._control = control
    launcher._supervisor = SimpleNamespace(deadline=control.deadline, close=lambda: None)
    monkeypatch.setattr(launcher, 'check_available', lambda *_: None)
    monkeypatch.setattr(launcher, '_quiet', lambda: None)
    sent, pending = [], list(candidates)
    monkeypatch.setattr(launcher, '_send', lambda raw: sent.append(json.loads(raw)))
    def reply():
        candidate = pending.pop(0)
        return protocol.receipt(sent[-1], candidate, {
            'executions_reserved': launcher._snapshot['executions_reserved'] + 1,
            'output_bytes_reserved': launcher._snapshot['output_bytes_reserved'] + sent[-1]['action']['parameters']['max_output_bytes']})
    monkeypatch.setattr(launcher, '_reply', reply)
    return launcher, control, sent


@pytest.mark.parametrize('configuration', ('A', 'B'))
def test_host_keeps_both_expiry_refusals_and_replays_strict_owner_context(monkeypatch, configuration):
    chosen, previous, candidates = refusals(configuration)
    launcher, control, sent = host(monkeypatch, chosen, previous, candidates)
    policy = contract.validate_policy(chosen['policy'], chosen['selection'])
    try:
        for candidate in candidates:
            raw = candidate['name_tls_refusal']['action']
            expected = context.validate_result_context(candidate, chosen['identity'], previous=previous,
                tool_id=raw['tool_id'], execution_status='blocked', runtime=chosen['runtime'])
            assert launcher.run(parse_action(raw), policy, control=control) == candidate
            assert launcher._lab_context == expected
            assert not launcher._closed
            previous = expected
        assert [row['sequence'] for row in sent] == [2, 3]
        assert launcher.snapshot == {'executions_reserved': 3,
            'output_bytes_reserved': sum(contract.action_bounds(slot)['output_bytes'] for slot in ('dns_1', 'http', 'tls'))}
        assert candidates[-1]['name_tls_ledger']['counters']['actions'] == 1
        assert candidates[-1]['name_tls_ledger']['counters']['connections'] == 1
    finally:
        launcher.close()


@pytest.mark.parametrize('change', ('reason', 'source', 'sequence', 'bytes', 'messages', 'counter', 'topology'))
def test_host_rejects_malformed_refusal_after_envelope_acceptance(monkeypatch, change):
    chosen, previous, candidates = refusals()
    candidate = candidates[0]
    if change == 'reason': candidate['name_tls_refusal']['reason'] = 'operation_plan_changed'
    elif change == 'source': candidate['name_tls_refusal']['source'] = 'owner_terminal'
    elif change == 'sequence': candidate['name_tls_refusal']['execution_sequence'] = True
    elif change == 'bytes': candidate['bytes_received'] = 1
    elif change == 'messages': candidate['name_tls_messages'].pop()
    elif change == 'counter': candidate['name_tls_ledger']['counters']['connections'] = 0
    else: candidate['name_tls_topology_parent_observation']['payload_pid'] = True
    launcher, control, sent = host(monkeypatch, chosen, previous, [candidate])
    assert protocol.result(candidate, launcher._config) is candidate
    with pytest.raises(IsolationUnavailable):
        launcher.run(parse_action(candidate['name_tls_refusal']['action']),
                     contract.validate_policy(chosen['policy'], chosen['selection']), control=control)
    assert launcher._closed and len(sent) == 1
    assert launcher._sequence == 1 and launcher.snapshot['executions_reserved'] == 1


@pytest.mark.parametrize('profile', tuple(protocol.PROFILES))
def test_original_result_statuses_are_unchanged_for_every_profile(profile):
    config = {'profile': profile, 'case': {'case': 'N14'}}
    for status in ('succeeded', 'failed', 'timeout', 'output_limit'):
        value = {'status': status, 'backend': protocol.PROFILES[profile], 'results': []}
        assert protocol.result(value, config) is value
    for status in ('cancelled', 'approved', True, None):
        value = {'status': status, 'backend': protocol.PROFILES[profile], 'results': [], 'name_tls_refusal': {}}
        with pytest.raises(ValueError, match='invalid_launcher_result'):
            protocol.result(value, config)


@pytest.mark.parametrize('profile', tuple(profile for profile in protocol.PROFILES if profile != contract.PROFILE))
def test_other_profiles_cannot_admit_name_tls_blocked_envelopes(profile):
    value = {'status': 'blocked', 'backend': protocol.PROFILES[profile], 'results': [], 'name_tls_refusal': {}}
    with pytest.raises(ValueError, match='invalid_launcher_result'):
        protocol.result(value, {'profile': profile, 'case': {'case': 'N14'}})


@pytest.mark.parametrize('case', tuple(case for case in public.CASES if case != 'N14'))
def test_non_n14_name_tls_cases_cannot_admit_blocked_envelopes(case):
    value = {'status': 'blocked', 'backend': contract.BACKEND, 'results': [], 'name_tls_refusal': {}}
    with pytest.raises(ValueError, match='invalid_launcher_result'):
        protocol.result(value, {'profile': contract.PROFILE, 'case': contract.selection('A', case)})


@pytest.mark.parametrize('case', (None, 'N14', [], {}, {'case': True}, {'case': 'N14 '}))
def test_blocked_envelope_requires_selected_n14_case(case):
    value = {'status': 'blocked', 'backend': contract.BACKEND, 'results': [], 'name_tls_refusal': {}}
    with pytest.raises(ValueError, match='invalid_launcher_result'):
        protocol.result(value, {'profile': contract.PROFILE, 'case': case})


@pytest.mark.parametrize('refusal', (None, False, [], 'owner_arm', 1))
def test_blocked_envelope_requires_refusal_object(refusal):
    value = {'status': 'blocked', 'backend': contract.BACKEND, 'results': [], 'name_tls_refusal': refusal}
    with pytest.raises(ValueError, match='invalid_launcher_result'):
        protocol.result(value, {'profile': contract.PROFILE, 'case': contract.selection('A', 'N14')})
