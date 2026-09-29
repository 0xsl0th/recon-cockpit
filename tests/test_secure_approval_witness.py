"""Pure consent binding/expiry contracts and pre-I/O option refusal."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import approval_witness as witness, cli, launcher_protocol
from recon_cockpit.secure_agent.approvals import ApprovalStore
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.authorized_execution import AuthorizedFixtureBackend
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.planner import proposal
from recon_cockpit.secure_agent.session import SessionLimits
from scripts.secure_agent_control_plane_demo import demo_policy
from test_secure_fixture_launcher import config, runtime


def example():
    policy, action = demo_policy(approval=True), parse_action(proposal())
    configuration = config(policy=policy.to_dict())
    source = {'version': '1', 'broker_id': str(uuid4()), 'device': 1, 'inode': 2}
    initial = {**configuration, 'broker_id': source['broker_id'], 'deadline': 130}
    store = ApprovalStore(clock=lambda: 100)
    grant = store.issue(action, policy)
    assert store.consume_with_grant(grant.reference, action, policy) == (None, grant)
    proof = witness.witness(initial, action, grant, 1, 2, 101)
    return configuration, action, source, proof


def test_consumed_grant_keeps_original_expiry_and_no_bearer_secret():
    configuration, action, source, proof = example()
    assert proof['issued_at'] == 101 and proof['expires_at'] == 105
    assert witness.validate(proof, configuration, action, source, 1, 0, 102, 130) == (2, 105)
    assert set(proof) == {'version', 'broker_id', 'session_id', 'policy_digest', 'action_id',
                         'action_digest', 'sequence', 'consume_sequence', 'issued_at', 'expires_at'}
    with pytest.raises(ValueError):
        witness.validate(proof, configuration, action, source, 1, 0, 105, 130)


@pytest.mark.parametrize('change', [
    {'version': '2'}, {'broker_id': str(uuid4())}, {'session_id': str(uuid4())},
    {'policy_digest': 'f'*64}, {'action_id': str(uuid4())}, {'action_digest': '0'*64},
    {'sequence': True}, {'sequence': 0}, {'sequence': 2}, {'consume_sequence': True},
    {'consume_sequence': 0}, {'consume_sequence': 33}, {'issued_at': True},
    {'issued_at': float('nan')}, {'issued_at': float('inf')}, {'issued_at': 103},
    {'issued_at': 97}, {'expires_at': True}, {'expires_at': float('nan')},
    {'expires_at': float('inf')}, {'expires_at': 102}, {'expires_at': 131},
    {'expires_at': 110}, {'approved': True}, {'reference': 'f'*48},
])
def test_forged_expired_or_replayed_proof_refuses(change):
    configuration, action, source, proof = example()
    with pytest.raises(ValueError):
        witness.validate({**proof, **change}, configuration, action, source, 1, 0, 102, 130)


@pytest.mark.parametrize('fault', ['action', 'policy', 'allow', 'consume_replay', 'ceiling'])
def test_canonical_bindings_and_sequence_ceiling(fault):
    configuration, action, source, proof = example()
    if fault == 'action':
        action = replace(action, rationale='changed')
    if fault == 'policy':
        configuration['policy']['policy_version'] = 'changed'
    if fault == 'allow':
        configuration['policy'] = demo_policy().to_dict()
    if fault == 'ceiling':
        proof['sequence'] = 17
    with pytest.raises(ValueError):
        witness.validate(proof, configuration, action, source, 17 if fault == 'ceiling' else 1,
                         2 if fault == 'consume_replay' else 0, 102, 130)


@pytest.mark.parametrize('change', [{'broker_id': 'bad'}, {'version': '2'}, {'device': True},
                                    {'inode': -1}, {'reset': True}, {'path': '/tmp/forged'}])
def test_invalid_bootstrap_source_refuses(change):
    configuration, _, source, _ = example()
    init = {'configuration': configuration, 'runtime': runtime(), 'deadline': 130,
            'audit_witness': {'version': '1', 'writer_id': str(uuid4()), 'device': 1, 'inode': 2},
            'approval_witness': {**source, **change}}
    with pytest.raises(ValueError):
        launcher_protocol.initial(init, 100)


def test_approval_gate_cannot_omit_audit_gate():
    configuration, _, source, _ = example()
    with pytest.raises(ValueError):
        launcher_protocol.initial({'configuration': configuration, 'runtime': runtime(),
                                   'deadline': 130, 'approval_witness': source}, 100)


def test_atomic_consumption_has_one_winner_and_never_extends_ttl():
    policy, action = demo_policy(approval=True), parse_action(proposal())
    now = [100]
    store = ApprovalStore(clock=lambda: now[0])
    grant = store.issue(action, policy)
    now[0] = 104
    with ThreadPoolExecutor(max_workers=8) as pool:
        replies = list(pool.map(lambda _: store.consume_with_grant(grant.reference, action, policy), range(8)))
    assert replies.count((None, grant)) == 1
    assert replies.count(('approval_unknown_or_replayed', None)) == 7
    assert grant.expires_at == 105


@pytest.mark.parametrize('fault', ['missing', 'changed', 'expired'])
def test_failed_consumption_returns_no_grant_and_burns(fault):
    policy, action = demo_policy(approval=True), parse_action(proposal())
    now = [100]
    store = ApprovalStore(clock=lambda: now[0])
    grant = store.issue(action, policy)
    if fault == 'expired':
        now[0] = 105
    reason, consumed = store.consume_with_grant(None if fault == 'missing' else grant.reference,
        replace(action, rationale='changed') if fault == 'changed' else action, policy)
    assert reason and consumed is None
    if fault != 'missing':
        assert store.consume(grant.reference, action, policy) == 'approval_unknown_or_replayed'


@pytest.mark.parametrize('fault', ['no_audit', 'wrong_session', 'wrong_policy', 'wrong_service'])
def test_launcher_requires_exact_approval_service_bound_to_bootstrap(fault):
    policy, session = demo_policy(approval=True), str(uuid4())
    with LinuxApprovalService(replace(policy, policy_version='other') if fault == 'wrong_policy' else policy,
                              str(uuid4()) if fault == 'wrong_session' else session, launch_witness=True) as service:
        with pytest.raises(ValueError):
            LinuxFixtureLauncher(AuthorizedFixtureBackend(policy, session, SessionLimits(), execute=True),
                                 audit=None if fault == 'no_audit' else object(),
                                 approvals=object() if fault == 'wrong_service' else service)
        assert service._witness_writer is None and service.boundary_checks is None


@pytest.mark.parametrize('args', [[], ['--mock'], ['--control-plane-mock', 'three_step', '--fixture'],
    ['--workflow-assessment', 'a', '--owned-lab', '--isolated-audit', '--isolated-approvals',
     '--isolated-launch-admission', '--isolated-launcher']])
def test_cli_missing_prerequisites_refuses_before_io(args, monkeypatch):
    monkeypatch.setattr(cli, '_read_bounded', lambda *_: pytest.fail('unexpected policy read'))
    with pytest.raises(SystemExit) as exc:
        cli.main([*args, '--require-launch-approval'])
    assert exc.value.code == 2
