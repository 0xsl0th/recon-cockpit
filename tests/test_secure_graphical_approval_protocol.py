"""Portable graphical bootstrap/cookie custody tests; not native GUI evidence."""

import os
from pathlib import Path
import struct
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import approval_protocol as common
from recon_cockpit.secure_agent import graphical_approval_isolation as isolation
from recon_cockpit.secure_agent import graphical_approval_protocol as graphical
from recon_cockpit.secure_agent.approvals import ApprovalUnavailable
from scripts.secure_agent_control_plane_demo import demo_policy


def initial():
    return {'version': '1', 'frontend': 'graphical_v1', 'broker_id': str(uuid4()),
            'session_id': str(uuid4()), 'policy': demo_policy(approval=True).to_dict(),
            'deadline': 60, 'display': ':20.0', 'display_socket': [4, 50]}


def authority(*, number=b'20', address=b'owned-host', family=256,
              name=b'MIT-MAGIC-COOKIE-1', cookie=b'a' * 16):
    fields = (address, number, name, cookie)
    return struct.pack('!H', family) + b''.join(struct.pack('!H', len(field)) + field for field in fields)


@pytest.mark.parametrize('value', [':0', ':1.0', ':65535', ':4096.0'])
def test_canonical_local_display(value):
    result = graphical.canonical_display(value)
    assert result.endswith('.0') and graphical.canonical_display(result) == result


@pytest.mark.parametrize('value', [None, True, 1, [], '', ':', ':01', ':1.1', ':65536',
    ':100000', 'localhost:1', 'tcp/localhost:1', 'unix:1', '/tmp/X1', ':1\n', ':1.0.0', ':1;echo'])
def test_remote_or_ambiguous_displays_are_rejected(value):
    with pytest.raises(ValueError):
        graphical.canonical_display(value)


def test_bootstrap_binds_fixed_frontend_and_no_terminal():
    value = initial()
    assert graphical.initial(value, 10).require_approval
    value['witness'] = [1, 2]
    assert graphical.initial(value, 10).digest == demo_policy(approval=True).digest
    assert 'terminal_operations_restricted' not in graphical.CHECKS
    assert graphical.CHECKS - common.CHECKS == {'display_bound', 'graphical_input_owned'}
    with pytest.raises(ValueError):
        common.initial(value, 10)


@pytest.mark.parametrize('change', [
    {'version': 1}, {'version': '2'}, {'frontend': 'terminal'}, {'frontend': True},
    {'deadline': 10}, {'deadline': True}, {'deadline': 611}, {'deadline': float('nan')},
    {'deadline': float('inf')}, {'display': ':20'}, {'display': ':20.1'},
    {'display_socket': [1]}, {'display_socket': [True, 2]}, {'display_socket': [-1, 2]},
    {'display_socket': (1, 2)}, {'witness': [1]}, {'witness': [1, False]},
    {'session_id': 'not-a-session'}, {'broker_id': 'not-a-broker'}, {'policy': {}},
    {'approved': True}, {'terminal': [1, 2, 3]}, {'cookie': 'secret'},
])
def test_graphical_bootstrap_rejects_unsafe_or_ambiguous_fields(change):
    value = initial()
    value.update(change)
    with pytest.raises(ValueError):
        graphical.initial(value, 10)


def test_authority_subset_contains_only_selected_local_cookie():
    selected = authority(cookie=b'x' * 16)
    raw = (authority(number=b'21', cookie=b'y' * 16)
           + authority(address=b'other-host', cookie=b'z' * 16)
           + authority(family=0, address=b'\x7f\x00\x00\x01', cookie=b'b' * 16)
           + selected)
    expected = authority(address=b'', family=65535, cookie=b'x' * 16)
    assert isolation.select_authority(raw, ':20.0', b'owned-host') == expected
    assert isolation.select_authority(selected + selected, ':20', b'owned-host') == expected
    assert isolation.select_authority(expected, ':20', b'owned-host') == expected


@pytest.mark.parametrize('raw', [b'', b'\x01', b'\x01\x00\xff\xff', b'a' * 65537,
    authority()[:-1], authority() + b'\0', authority(number=b'21'),
    authority(address=b'other-host'), authority(family=0), authority(name=b'other-method'),
    authority(cookie=b'a' * 15), authority(cookie=b'a' * 17),
    authority() + authority(cookie=b'b' * 16),
])
def test_authority_rejects_malformed_missing_or_conflicting_cookie(raw):
    with pytest.raises(ValueError):
        isolation.select_authority(raw, ':20', b'owned-host')


def test_private_authority_reader_rejects_symlink_directory_and_writable_file(tmp_path):
    path = tmp_path / 'auth'
    path.write_bytes(authority())
    path.chmod(0o600)
    assert isolation._read_authority(path) == authority()
    link = tmp_path / 'link'
    link.symlink_to(path)
    with pytest.raises(OSError):
        isolation._read_authority(link)
    with pytest.raises(ApprovalUnavailable):
        isolation._read_authority(tmp_path)
    path.chmod(0o622)
    with pytest.raises(ApprovalUnavailable):
        isolation._read_authority(path)
    path.chmod(0o600)
    path.write_bytes(b'a' * 65537)
    with pytest.raises(ApprovalUnavailable):
        isolation._read_authority(path)


@pytest.mark.parametrize('witness', [False, True])
def test_fixed_command_mounts_one_socket_and_sealed_subset_not_authority_source(monkeypatch, tmp_path, witness):
    resources = tuple(str(tmp_path.resolve() / name) for name in ('tcl', 'tk', 'fonts', 'cache'))
    for directory in resources:
        Path(directory).mkdir()
    monkeypatch.setattr(isolation, 'RUNTIME_DIRECTORIES', resources)
    monkeypatch.setattr(isolation, '_namespaces', lambda: dict.fromkeys(('user', 'net', 'mnt', 'pid'), 'test'))
    monkeypatch.setattr(isolation, '_trusted_program', lambda _: '/usr/bin/bwrap')
    argv = isolation.command('/usr/lib/python3.test', [('/lib/runtime', '/lib/runtime')], 'a' * 64,
        display=':20.0', socket_path='/tmp/.X11-unix/X20', authority_fd=7,
        font_config_fd=8, launch_witness=witness)
    assert '--unshare-net' in argv and '--clearenv' in argv
    assert argv.count('/tmp/.X11-unix/X20') == 2
    assert '/tmp/.X11-unix' not in argv and '/home' not in argv and '/dev/tty' not in argv
    assert not any('Xauthority' in item for item in argv)
    assert ['--ro-bind-data', '7', graphical.AUTHORITY_PATH] == argv[argv.index('--ro-bind-data'):][:3]
    assert '/app/approval_runtime/graphical_approval_worker.py' in argv
    assert ('launch-witness' in argv) is witness
    assert '--setenv' in argv and graphical.FONTCONFIG_PATH in argv
    assert 'approval_worker.py' not in argv


def test_command_rejects_socket_substitution_before_runtime_work():
    with pytest.raises(ApprovalUnavailable):
        isolation.command('unused', [], 'a' * 64, display=':20', socket_path='/tmp/X21',
            authority_fd=7, font_config_fd=8, launch_witness=True)


def test_graphical_channel_retains_no_affirmative_answer_operation():
    from recon_cockpit.secure_agent.planner import proposal
    value = {'version': '1', 'broker_id': str(uuid4()), 'session_id': str(uuid4()),
        'sequence': 1, 'operation': 'review', 'action': proposal(), 'policy_digest': 'a' * 64}
    assert common.request(value, value['broker_id'], value['session_id'], 1)
    for extra in ({'approved': True}, {'answer': 'approve'}, {'operation': 'approve'}, {'operation': 'issue'}):
        with pytest.raises(ValueError):
            common.request({**value, **extra}, value['broker_id'], value['session_id'], 1)


def test_service_selection_is_inert_and_defaults_to_terminal(monkeypatch):
    from recon_cockpit.secure_agent import approval_isolation
    from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
    from recon_cockpit.secure_agent.models import parse_action
    from recon_cockpit.secure_agent.planner import proposal

    policy, action = demo_policy(approval=True), parse_action(proposal())

    class NoEnvironment(dict):
        def __getitem__(self, key):
            raise AssertionError('inert service read environment')
        def get(self, *args):
            raise AssertionError('inert service read environment')

    def forbidden(*args, **kwargs):
        pytest.fail('inert service tried to open a review surface')

    monkeypatch.setattr(approval_isolation, '_open_terminal', forbidden)
    monkeypatch.setattr(isolation, 'start', forbidden)
    with monkeypatch.context() as guarded:
        guarded.setattr(os, 'environ', NoEnvironment())
        for options, expected in (({}, 'terminal'), ({'frontend': 'terminal'}, 'terminal'),
                                  ({'frontend': 'graphical_v1'}, 'graphical_v1')):
            with LinuxApprovalService(policy, str(uuid4()), **options) as service:
                assert service._frontend == expected
                assert service.consume(None, action, policy) == 'approval_missing'
                assert service.consume('a' * 48, action, policy) == 'approval_unknown_or_replayed'
                assert service.boundary_checks is None
                assert service._control is service._channel is service._supervisor is None
                for operation in ('approve', 'deny', 'issue', 'reset', 'submit_answer', 'restore'):
                    assert not hasattr(service, operation)


@pytest.mark.parametrize('frontend', [None, True, 1, [], {}, '', 'graphical', 'terminal_v1', 'custom.module'])
def test_service_rejects_unknown_frontend(frontend):
    from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
    with pytest.raises(ValueError, match='invalid_approval_frontend'):
        LinuxApprovalService(demo_policy(approval=True), str(uuid4()), frontend=frontend)


@pytest.mark.parametrize('kind', ['missing', 'wrong_type', 'custom_clock', 'extended_lifetime'])
def test_graphical_start_retains_original_control_validation(monkeypatch, kind):
    from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.models import parse_action
    from recon_cockpit.secure_agent.planner import proposal

    monkeypatch.setattr(isolation, 'start', lambda *_: pytest.fail('invalid control reached graphical bootstrap'))
    controls = {'missing': None, 'wrong_type': object(),
        'custom_clock': ExecutionControl(time.monotonic() + 10, clock=lambda: time.monotonic()),
        'extended_lifetime': ExecutionControl(time.monotonic() + common.MAX_LIFETIME + 100)}
    with LinuxApprovalService(demo_policy(approval=True), str(uuid4()), frontend='graphical_v1') as service:
        with pytest.raises(ApprovalUnavailable):
            service.review(parse_action(proposal()), service._policy, control=controls[kind])
        assert service._closed and service.boundary_checks is None


def test_graphical_start_retains_original_witness_custody(monkeypatch):
    from types import SimpleNamespace
    from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.models import parse_action
    from recon_cockpit.secure_agent.planner import proposal

    monkeypatch.setattr(isolation, 'start', lambda *_: pytest.fail('unbound witness reached graphical bootstrap'))
    for take_and_seal in (False, True):
        with LinuxApprovalService(demo_policy(approval=True), str(uuid4()),
                frontend='graphical_v1', launch_witness=True) as service:
            if take_and_seal:
                # Portable custody double, not socket/kernel evidence.
                closed = []
                service._witness_taken = True
                service._witness_writer = SimpleNamespace(close=lambda: closed.append(True))
                with pytest.raises(ApprovalUnavailable):
                    service.take_launch_witness()
                service.seal_launch_witness()
                assert closed == [True] and service._witness_writer is None
            with pytest.raises(ApprovalUnavailable):
                service.review(parse_action(proposal()), service._policy,
                    control=ExecutionControl(time.monotonic() + 10))
            assert service._closed and service.boundary_checks is None
