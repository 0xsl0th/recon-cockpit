"""One-action stock diagnostics preserve independent authority and witness gates."""

from copy import deepcopy
import hashlib
from pathlib import Path
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import stock_http_contract as contract, stock_http_spec as spec
from recon_cockpit.secure_agent import stock_http_runtime as daemon_runtime
from recon_cockpit.secure_agent import launch_admission as admission, launcher_protocol as launcher
from recon_cockpit.secure_agent.stock_http_execution import consume_launch
from recon_cockpit.secure_agent.models import parse_action
from test_secure_network_tools_runtime import manifest as native_manifest
from test_secure_fixture_launcher import runtime as base_runtime

SESSION = str(UUID(int=881))
NONCE = 'a' * 64
HOST = {name: name + ':[100]' for name in ('user', 'net', 'mnt', 'pid')}


@pytest.mark.parametrize('profile', (contract.PROFILE, 'configurable_owned_lab', 'fixture'))
def test_parent_private_peer_mount_is_stock_only_and_keeps_aggregate_tmpfs_bound(monkeypatch, profile):
    from recon_cockpit.secure_agent import launcher_isolation
    monkeypatch.setattr(launcher_isolation, '_trusted_program', lambda name: '/usr/bin/' + name)
    # This constructs argv only; real namespace discovery belongs to native
    # integration tests. Keep the bootstrap binding observable on any POSIX host.
    monkeypatch.setattr(launcher_isolation, '_namespaces', lambda: dict(HOST))
    selected = launcher_isolation.LinuxFixtureLauncher.__new__(launcher_isolation.LinuxFixtureLauncher)
    selected._config = {'profile': profile}
    selected._witness_source = selected._approval_source = None
    argv = selected._command({'stdlib': '/stdlib'}, [], 'a' * 64)
    assert argv[-9:] == [
        '/usr/bin/python3', '-I', '-S', '/app/recon_cockpit/secure_agent/launcher_worker.py',
        'a' * 64, *(HOST[name] for name in ('user', 'net', 'mnt', 'pid'))]
    mounts = {}
    for index, item in enumerate(argv):
        if item == '--tmpfs':
            assert argv[index - 2] == '--size'
            mounts[argv[index + 1]] = int(argv[index - 1])
    assert sum(mounts.values()) == 1048576
    if profile == contract.PROFILE:
        assert mounts == {'/tmp': 262144, '/stock-peer': 786432}
        peer = argv.index('/stock-peer')
        assert argv[peer - 5:peer + 1] == ['--perms', '0700', '--size', '786432', '--tmpfs', '/stock-peer']
    else:
        assert mounts == {'/tmp': 1048576}
        assert '/stock-peer' not in argv


def runtime(configuration='A', case='O1'):
    rows = [(daemon_runtime.EXECUTABLE, daemon_runtime.DESTINATION, b'native')]
    rows += [(daemon_runtime.LIBRARY_ROOT + 'ld-linux-x86-64.so.2' if dst == daemon_runtime.INTERPRETER else dst,
              dst, b'native') for dst in sorted(daemon_runtime.DEPENDENCIES)]
    rows += list(spec.compiled_files(configuration, case))
    daemon = {'schema_version': '1', 'profile': daemon_runtime.PROFILE,
        **contract.selection(configuration, case), 'executable': daemon_runtime.DESTINATION,
        'interpreter': daemon_runtime.INTERPRETER, 'dependency_kind': 'elf_linked_dependencies_only',
        'runtime_closure_verified': False, 'daemon_execution_performed': False,
        'files': [{'source': source, 'destination': destination, 'size': len(raw),
                   'sha256': hashlib.sha256(raw).hexdigest()} for source, destination, raw in sorted(rows, key=lambda row: row[1])]}
    return {'daemon': daemon, 'client': native_manifest('nmap_service_identify_v1') if case in ('O5', 'O6') else None}


def identity(configuration='A', case='O1'):
    selected = contract.selection(configuration, case)
    return {'version': '1', 'profile': contract.PROFILE, 'instance_id': str(UUID(int=882)),
            'session_id': SESSION, **selected, **contract.runtime_digests(runtime(configuration, case), selected)}


def configuration(config='A', case='O1'):
    selected = contract.selection(config, case)
    return {'version': '1', 'service_id': str(UUID(int=883)), 'session_id': SESSION,
        'policy': contract.policy_for_selection(selected).to_dict(), 'limits': contract.limits(selected),
        'execute': True, 'profile': contract.PROFILE, 'case': selected}


def request(config, sequence=1, *, operation='execute', permit=None):
    value = {'version': '1', 'service_id': config['service_id'], 'session_id': config['session_id'],
        'sequence': sequence, 'operation': operation, 'action': contract.action(config['case']),
        'policy_digest': admission.digest(config['policy'])}
    if operation == 'redeem': value['permit'] = permit
    return value


def envelope(config='A', case='O1'):
    selected = contract.selection(config, case)
    action = parse_action(contract.action(selected))
    policy = contract.policy_for_selection(selected)
    limits = contract.limits(selected)
    return {'mode': contract.PROFILE, 'selection': selected, 'identity': identity(config, case),
        'runtime': runtime(config, case), 'namespaces': {key: key + ':[200]' for key in HOST},
        'launch': {'schema_version': '1', 'mode': contract.PROFILE, 'execute': True,
            'session_id': SESSION, 'nonce': NONCE, 'sequence': 1,
            'action': action.to_dict(), 'action_digest': action.digest,
            'policy': policy.to_dict(), 'policy_digest': policy.digest,
            'limits': limits, 'limits_digest': admission.digest(limits), 'deadline': 150,
            'output_reserved_before': 0, 'output_reserved_after': limits['max_output_bytes'],
            'host_namespaces': HOST}}


def verify(value, *, nonce=NONCE):
    raw = spec.encode(value)
    return consume_launch(raw, nonce, hashlib.sha256(raw).hexdigest(), now=100)


@pytest.mark.parametrize('config,case', spec.TRIALS)
def test_each_selection_has_exact_independent_action_limits_and_runtime(config, case):
    value = envelope(config, case)
    req, deadline, namespaces, runtime_hash = verify(value)
    assert req['selection'] == contract.selection(config, case)
    assert req['target'] == value['launch']['action']['target']
    assert req['parameters'] == value['launch']['action']['parameters']
    assert req['scope'] == contract.scope(value['selection']) and req['endpoint_id'] == 'http'
    assert deadline == 150 and namespaces == value['namespaces']
    assert (runtime_hash is None) == (case not in ('O5', 'O6'))
    config = configuration(config, case)
    assert admission.configuration(config) == config
    assert launcher.request(request(config), config, 1).to_dict() == value['launch']['action']


def test_identical_header_action_still_requires_distinct_case_bound_approval_policy():
    left, right = contract.selection('A', 'O1'), contract.selection('A', 'R1')
    assert contract.action(left) == contract.action(right)
    assert contract.policy_for_selection(left).digest != contract.policy_for_selection(right).digest
    policies = [contract.policy_for_selection(contract.selection(*pair)) for pair in spec.TRIALS]
    assert len({policy.policy_version for policy in policies}) == 26
    assert all(len(policy.policy_version) <= 64 for policy in policies)
    config = configuration()
    config['policy'] = contract.policy_for_selection(right).to_dict()
    with pytest.raises(ValueError, match='policy_binding_changed'): admission.configuration(config)


@pytest.mark.parametrize('field', ('max_steps', 'max_runtime_seconds', 'max_output_bytes'))
@pytest.mark.parametrize('change', (1, -1, True))
def test_reservation_cannot_change_or_weaken_fixed_one_action_contract(field, change):
    config = configuration()
    config['limits'][field] = change if type(change) is bool else config['limits'][field] + change
    with pytest.raises(ValueError): admission.configuration(config)


def test_single_admission_burns_on_redeem_and_does_not_refund_or_allow_second_action():
    config = configuration()
    state = admission.AdmissionState({'configuration': config, 'deadline': 160}, clock=lambda: 100)
    granted = state.handle(request(config, operation='admit'))
    assert granted['reason'] is None and granted['snapshot'] == {'executions_reserved': 1, 'output_bytes_reserved': 2048}
    for sequence, expected in ((2, None), (3, 'admission_unknown_or_replayed')):
        assert state.handle(request(config, sequence, operation='redeem', permit=granted['permit']))['reason'] == expected
    denied = state.handle(request(config, 4, operation='admit'))
    assert denied['reason'] == 'admission_step_limit' and denied['snapshot'] == granted['snapshot']
    with pytest.raises(ValueError): launcher.request(request(config, 2), config, 2)


@pytest.mark.parametrize('fault', ('target', 'port', 'path', 'method', 'action_id', 'rationale', 'timeout', 'output'))
def test_changed_action_never_obtains_permit_or_launcher_execution(fault):
    config = configuration()
    value = request(config, operation='admit')
    action = value['action']
    if fault == 'target': action['target'] = '10.77.0.99'
    elif fault == 'port': action['parameters']['port'] = 8081
    elif fault == 'path': action['parameters']['path'] = '/private'
    elif fault == 'method': action['parameters']['method'] = 'HEAD'
    elif fault == 'action_id': action['action_id'] = str(UUID(int=999))
    elif fault == 'rationale': action['rationale'] = 'different'
    elif fault == 'timeout': action['parameters']['timeout_seconds'] = 2
    else: action['parameters']['max_output_bytes'] = 1024
    state = admission.AdmissionState({'configuration': config, 'deadline': 160}, clock=lambda: 100)
    denied = state.handle(value)
    assert denied['reason'] in ('admission_policy_denied', 'admission_profile_denied')
    assert denied['snapshot'] == {'executions_reserved': 0, 'output_bytes_reserved': 0}
    with pytest.raises(ValueError): launcher.request({**value, 'operation': 'execute'}, config, 1)


@pytest.mark.parametrize('fault', ('selection', 'owner_case', 'owner_session', 'owner_runtime', 'runtime_case',
    'runtime_hash', 'runtime_extra', 'client', 'outer_mode', 'inner_mode', 'execute', 'nonce',
    'session', 'sequence', 'sequence_bool', 'before', 'after', 'deadline', 'deadline_bool',
    'namespace', 'namespace_type', 'namespace_extra', 'action_target', 'action_port', 'action_path',
    'policy_case', 'policy_deny', 'steps', 'unknown', 'launch_unknown'))
def test_fresh_commitment_cannot_bypass_owner_policy_selection_runtime_or_reservation(fault):
    value = envelope()
    launch = value['launch']
    if fault == 'selection': value['selection'] = contract.selection('A', 'R1')
    elif fault == 'owner_case': value['identity']['case'] = 'R1'
    elif fault == 'owner_session': value['identity']['session_id'] = str(UUID(int=999))
    elif fault == 'owner_runtime': value['identity']['daemon_runtime_sha256'] = 'b' * 64
    elif fault == 'runtime_case': value['runtime'] = runtime('B', 'O1')
    elif fault == 'runtime_hash': value['runtime']['daemon']['files'][0]['sha256'] = 'b' * 64
    elif fault == 'runtime_extra': value['runtime']['extra'] = None
    elif fault == 'client': value['runtime']['client'] = native_manifest('nmap_service_identify_v1')
    elif fault == 'outer_mode': value['mode'] = 'configurable_owned_lab'
    elif fault == 'inner_mode': launch['mode'] = 'configurable_owned_lab'
    elif fault == 'execute': launch['execute'] = False
    elif fault == 'nonce': launch['nonce'] = 'b' * 64
    elif fault == 'session': launch['session_id'] = str(UUID(int=999))
    elif fault == 'sequence': launch['sequence'] = 2
    elif fault == 'sequence_bool': launch['sequence'] = True
    elif fault == 'before': launch['output_reserved_before'] = 1
    elif fault == 'after': launch['output_reserved_after'] = 2047
    elif fault == 'deadline': launch['deadline'] = 161
    elif fault == 'deadline_bool': launch['deadline'] = True
    elif fault == 'namespace': value['namespaces']['net'] = HOST['net']
    elif fault == 'namespace_type': value['namespaces']['net'] = 'user:[200]'
    elif fault == 'namespace_extra': value['namespaces']['extra'] = 'net:[200]'
    elif fault == 'action_target': launch['action']['target'] = '10.77.0.99'
    elif fault == 'action_port': launch['action']['parameters']['port'] = 8081
    elif fault == 'action_path': launch['action']['parameters']['path'] = '/private'
    elif fault == 'policy_case': launch['policy'] = contract.policy_for_selection(contract.selection('A', 'R1')).to_dict()
    elif fault == 'policy_deny': launch['policy']['allowed_targets'] = []
    elif fault == 'steps': launch['limits']['max_steps'] = 2
    elif fault == 'unknown': value['extra'] = True
    else: launch['extra'] = True
    for field in ('action', 'policy', 'limits'): launch[field + '_digest'] = admission.digest(launch[field])
    with pytest.raises(ValueError): verify(value)


def initial():
    config = configuration()
    config['owned_lab'] = identity()
    closure = base_runtime()
    closure['files'].append('/usr/bin/nsenter')
    closure['stock_http_runtime'] = runtime()
    return {'configuration': config, 'deadline': 160, 'runtime': closure,
        'audit_witness': {'version': '1', 'writer_id': str(UUID(int=990)), 'device': 1, 'inode': 2},
        'approval_witness': {'version': '1', 'broker_id': str(UUID(int=991)), 'device': 1, 'inode': 3}}


def test_launcher_requires_both_independent_witnesses_even_for_allow_policy():
    value = initial()
    assert launcher.initial(value, 100) == value['configuration']
    value['configuration']['policy'] = contract.policy_for_selection(value['configuration']['case'], require_approval=False).to_dict()
    assert launcher.initial(value, 100) == value['configuration']
    for key in ('audit_witness', 'approval_witness'):
        changed = deepcopy(value);del changed[key]
        with pytest.raises(ValueError): launcher.initial(changed, 100)
    for tag in (None, 'launch-witness', 'launch-preconditions', 'configurable-launch-preconditions'):
        with pytest.raises(ValueError): launcher.validate_runtime_tag(tag, value['configuration'], value['runtime'])
    launcher.validate_runtime_tag('stock-http-launch-preconditions', value['configuration'], value['runtime'])


def test_direct_host_backend_cannot_launch_without_independent_services():
    from recon_cockpit.secure_agent.stock_http_backend import AuthorizedStockHttpBackend
    from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
    from recon_cockpit.secure_agent.isolation import IsolationUnavailable
    backend = object.__new__(AuthorizedStockHttpBackend)
    with pytest.raises(IsolationUnavailable, match='witnessed'): backend.run(None, None)
    with pytest.raises(ValueError, match='isolated_audit_and_approval'): LinuxFixtureLauncher(backend)


def test_launcher_witness_order_precedes_owner_action():
    # Guard the required custody order independently of parser/process fixtures.
    from recon_cockpit.secure_agent import launcher_worker
    source = Path(launcher_worker.__file__).read_text()
    ordered = ['witness_reader.require(', 'approval_reader.require(', 'gate.admit(', 'gate.redeem(',
               'approval_reader.check_fresh(', 'owned.run(']
    positions = [source.index(value) for value in ordered]
    assert positions == sorted(positions)


def failed_result():
    # A genuinely attempted, refused run remains visible and inconclusive.
    ledger = {'schema_version': '1', 'configuration': 'A', 'case': 'O1',
        'armed': True, 'finalized': True, 'terminal_reason': 'closed', 'pending_connections': 0,
        'active_connections': 0, 'connections_attempted': 2, 'connections_admitted': 0,
        'connections_denied': 2, 'requests_validated': 0, 'requests_delivered': 0,
        'request_bytes_received': 0, 'request_bytes_delivered': 0, 'daemon_connections': 0,
        'daemon_response_bytes': 0, 'client_response_bytes': 0, 'original_response_hex': '',
        'transformed_response_hex': '', 'admissions_elapsed_ms': [], 'events': [
            {'kind': kind, 'elapsed_ms': connection, 'connection': connection, 'bytes': 0,
             'reason': 'not_armed' if kind == 'deny' else ''}
            for connection in (1, 2) for kind in ('attempt', 'deny')], 'writes': []}
    bounds = {'address_space_bytes': 268435456, 'file_descriptors': 64, 'scratch_bytes': 786432,
              'retained_evidence_bytes': 262144, 'aggregate_storage_bytes': 1048576, 'no_children': True}
    owner = {'recorder_namespaces': {key: key + ':[200]' for key in HOST},
        'daemon_namespaces': {key: key + ':[300]' for key in HOST}, 'witness_baselines': True,
        'recorder_bounds': dict(bounds), 'daemon_bounds': dict(bounds),
        'private_socket_unmounted_from_client': True, 'daemon_ready': True}
    receipt = {'connection_count': 0, 'request_count': 0, 'recorder': ledger, 'owner': owner}
    selected_identity = identity()
    return {'backend': contract.BACKEND, 'status': 'failed', 'results': [], 'tool_observation': None,
        'stock_http_owner': receipt,
        'owned_lab': {'identity': selected_identity, 'connection_count': 0, 'request_count': 0,
                      'owner_receipt_sha256': hashlib.sha256(spec.encode(receipt)).hexdigest()},
        'stock_http_closure': {'identity': selected_identity, 'status': 'closed', 'started': True,
            'connection_count': 0, 'request_count': 0, 'recorder': deepcopy(ledger),
            'processes_reaped': True, 'namespace_descriptors_closed': True}}


def test_result_context_retains_denied_attempts_without_claiming_useful_work():
    value = failed_result()
    context = contract.validate_result_context(value, identity(), tool_id=contract.action(contract.selection('A', 'O1'))['tool_id'], execution_status='failed')
    assert context['connection_count'] == 0
    assert value['stock_http_owner']['recorder']['connections_attempted'] == 2
    assert value['stock_http_owner']['recorder']['connections_denied'] == 2
    assert value['tool_observation'] is None


@pytest.mark.parametrize('fault', ('owner_hash', 'count', 'owner_count', 'namespace', 'bounds', 'flags',
    'unfinished', 'unarmed', 'owner_selection', 'cleanup_missing', 'cleanup_process', 'cleanup_namespace',
    'cleanup_counts', 'cleanup_ledger', 'observation', 'previous', 'wrong_tool'))
def test_result_acknowledgement_requires_matching_accounting_and_actual_owner_teardown(fault):
    value = failed_result()
    if fault == 'owner_hash': value['owned_lab']['owner_receipt_sha256'] = 'f' * 64
    elif fault == 'count': value['owned_lab']['connection_count'] = 1
    elif fault == 'owner_count': value['stock_http_owner']['connection_count'] = 1
    elif fault == 'namespace': value['stock_http_owner']['owner']['daemon_namespaces'] = value['stock_http_owner']['owner']['recorder_namespaces']
    elif fault == 'bounds': value['stock_http_owner']['owner']['recorder_bounds']['scratch_bytes'] *= 2
    elif fault == 'flags': value['stock_http_owner']['owner']['daemon_ready'] = 1
    elif fault == 'unfinished': value['stock_http_owner']['recorder'].update(finalized=False, terminal_reason='running')
    elif fault == 'unarmed': value['stock_http_owner']['recorder']['armed'] = False
    elif fault == 'owner_selection': value['stock_http_owner']['recorder']['case'] = 'N1'
    elif fault == 'cleanup_missing': del value['stock_http_closure']
    elif fault == 'cleanup_process': value['stock_http_closure']['processes_reaped'] = False
    elif fault == 'cleanup_namespace': value['stock_http_closure']['namespace_descriptors_closed'] = False
    elif fault == 'cleanup_counts': value['stock_http_closure']['connection_count'] = 1
    elif fault == 'cleanup_ledger': value['stock_http_closure']['recorder']['connections_attempted'] = 1
    elif fault == 'observation': value['tool_observation'] = {'invented': True}
    if fault != 'owner_hash':
        value['owned_lab']['owner_receipt_sha256'] = hashlib.sha256(spec.encode(value['stock_http_owner'])).hexdigest()
    with pytest.raises(ValueError):
        contract.validate_result_context(value, identity(), previous={} if fault == 'previous' else None,
            tool_id='configurable_nmap_service_v1' if fault == 'wrong_tool' else 'configurable_http_headers_v1', execution_status='failed')
