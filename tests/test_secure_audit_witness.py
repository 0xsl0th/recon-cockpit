"""Pure witness validation, transport framing and CLI refusal contracts."""

import array
import os
import socket
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import audit_witness as witness, audit_protocol, cli
from recon_cockpit.secure_agent.launcher_protocol import PROFILES, initial
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.planner import proposal
from scripts.secure_agent_control_plane_demo import demo_policy
from test_secure_fixture_launcher import config, runtime


def intent(action, policy, session, backend=PROFILES['fixture']):
    return {'event_type': 'execution_started', 'session_id': session,
            'action_id': action.action_id, 'action_digest': action.digest,
            'policy_digest': policy.digest, 'policy_version': policy.policy_version,
            'tool_id': action.tool_id, 'target': action.target, 'backend': backend,
            'decision': policy.evaluate(action).decision, 'execution_status': 'started'}


def example():
    configuration, action = config(), parse_action(proposal())
    source = {'version': '1', 'writer_id': str(uuid4()), 'device': 1, 'inode': 2}
    event = intent(action, demo_policy(), configuration['session_id'])
    proof = witness.witness(event, source['writer_id'], 3, 1, 100)
    return configuration, action, source, event, proof


def test_witness_binds_exact_durable_projection_and_original_event_digest():
    configuration, action, source, event, proof = example()
    assert witness.validate(proof, configuration, action, source, 1, 0, 101) == 3
    assert proof['intent'] == {key: event[key] for key in witness.FIELDS}
    assert proof['event_digest'] == audit_protocol.receipt(source['writer_id'], 3, audit_protocol.event_bytes(event))['event_digest']
    init = {'configuration': configuration, 'runtime': runtime(), 'deadline': 130, 'audit_witness': source}
    assert initial(init, 100) == configuration


@pytest.mark.parametrize('change', [
    {'version': '2'}, {'writer_id': str(uuid4())}, {'sequence': True}, {'sequence': 0},
    {'sequence': 2}, {'audit_sequence': 0}, {'audit_sequence': True}, {'audit_sequence': 1025},
    {'issued_at': True}, {'issued_at': float('nan')}, {'issued_at': float('inf')},
    {'issued_at': 102}, {'issued_at': 95}, {'event_digest': 'bad'}, {'approved': True},
])
def test_forged_stale_or_replayed_witnesses_refuse(change):
    configuration, action, source, _, proof = example()
    with pytest.raises(ValueError):
        witness.validate({**proof, **change}, configuration, action, source, 1, 0, 101)


@pytest.mark.parametrize('key', list(witness.FIELDS))
def test_any_changed_execution_identity_refuses(key):
    configuration, action, source, _, proof = example()
    proof['intent'][key] = 'changed'
    with pytest.raises(ValueError):
        witness.validate(proof, configuration, action, source, 1, 0, 101)


@pytest.mark.parametrize('change', [
    {'version': '2'}, {'writer_id': 'bad'}, {'device': True}, {'inode': -1},
    {'path': '/tmp/forged'}, {'reset': True},
])
def test_bootstrap_cannot_add_paths_reset_or_invalid_identity(change):
    configuration, _, source, _, _ = example()
    with pytest.raises(ValueError):
        initial({'configuration': configuration, 'runtime': runtime(), 'deadline': 130,
                 'audit_witness': {**source, **change}}, 100)


@pytest.mark.parametrize('change', [
    {'event_type': 'execution_finished'}, {'session_id': 'bad'}, {'action_id': 'bad'},
    {'action_digest': 'f'}, {'policy_digest': None}, {'decision': 'deny'}, {'decision': []},
    {'execution_status': 'succeeded'}, {'backend': 'x'*257},
])
def test_writer_rejects_malformed_launch_intents(change):
    _, _, source, event, _ = example()
    with pytest.raises(ValueError):
        witness.witness({**event, **change}, source['writer_id'], 3, 1, 100)


def test_audit_sequence_cannot_rewind_and_launch_ceiling_is_fixed():
    configuration, action, source, event, proof = example()
    with pytest.raises(ValueError):
        witness.validate(proof, configuration, action, source, 1, 3, 101)
    with pytest.raises(ValueError):
        witness.witness(event, source['writer_id'], 3, 17, 100)


@pytest.mark.parametrize('raw', [b'{}', b'', b'{"a":1,"a":2}', b'{"x":NaN}', b'[]'])
def test_rejected_bootstrap_packets_close_received_capabilities(raw):
    read, write = os.pipe()
    try:
        channel = SimpleNamespace(recvmsg=lambda *_: (raw, [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [read]).tobytes())], 0, None))
        with pytest.raises(ValueError):
            witness.receive(channel)  # No capabilities allowed on an ordinary witness.
        with pytest.raises(OSError):
            os.fstat(read)
    finally:
        os.close(write)


@pytest.mark.parametrize('flags', [socket.MSG_TRUNC, socket.MSG_CTRUNC])
def test_truncated_witness_packets_refuse(flags):
    channel = SimpleNamespace(recvmsg=lambda *_: (b'{}', [], flags, None))
    with pytest.raises(ValueError):
        witness.receive(channel)


@pytest.mark.parametrize('args', [[], ['--mock'], ['--control-plane-mock', 'three_step', '--fixture'],
    ['--control-plane-mock', 'three_step', '--fixture', '--isolated-audit', '--isolated-approvals', '--isolated-launch-admission']])
def test_cli_missing_prerequisites_refuses_before_io(args, monkeypatch):
    monkeypatch.setattr(cli, '_read_bounded', lambda *_: pytest.fail('unexpected policy read'))
    with pytest.raises(SystemExit) as exc:
        cli.main([*args, '--require-launch-audit'])
    assert exc.value.code == 2
