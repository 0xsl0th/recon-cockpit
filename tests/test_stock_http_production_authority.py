"""Production implementation/runtime identity never weakens launch authority."""

from copy import deepcopy
import hashlib
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import stock_http_production_contract as contract
from recon_cockpit.secure_agent import stock_http_spec as spec, stock_apache_spec
from recon_cockpit.secure_agent import stock_apache_runtime
from recon_cockpit.secure_agent import launch_admission as admission, launcher_protocol as launcher
from recon_cockpit.secure_agent.stock_http_production_execution import consume_launch
from recon_cockpit.secure_agent.models import parse_action
from test_secure_stock_http_authority import runtime as nginx_runtime, failed_result as diagnostic_failure
from test_secure_stock_http_authority import HOST, NONCE, SESSION, base_runtime


def runtime(implementation='apache', configuration='A', case='O1'):
    result = nginx_runtime(configuration, case)
    if implementation == 'nginx':
        return result
    module = stock_apache_runtime
    rows = [(source, destination, b'native') for destination, source in module._native_files().items()]
    rows += [(module.LIBRARY_ROOT + 'ld-linux-x86-64.so.2' if destination == module.INTERPRETER else destination,
              destination, b'native') for destination in module.DEPENDENCIES]
    rows += list(stock_apache_spec.compiled_files(configuration, case))
    result['daemon'] = {'schema_version': '1', 'profile': module.PROFILE,
        'configuration': configuration, 'case': case,
        'selection_sha256': stock_apache_spec.selection_digest(configuration, case),
        'executable': module.DESTINATION, 'interpreter': module.INTERPRETER,
        'modules': module._modules(), 'elf_dependencies': module._elf_dependencies(),
        'dependency_kind': 'fixed_modules_and_elf_linked_dependencies_only',
        'runtime_closure_verified': False, 'daemon_execution_performed': False,
        'files': [{'source': source, 'destination': destination, 'size': len(raw),
                   'sha256': hashlib.sha256(raw).hexdigest()} for source, destination, raw in sorted(rows, key=lambda row: row[1])]}
    return result


def identity(implementation='apache', configuration='A', case='O1'):
    selected = contract.selection(implementation, configuration, case)
    return {'version': '1', 'profile': contract.PROFILE, 'instance_id': str(UUID(int=1882)),
            'session_id': SESSION, **selected, **contract.runtime_digests(runtime(implementation, configuration, case), selected)}


def configuration(implementation='apache', config='A', case='O1'):
    selected = contract.selection(implementation, config, case)
    return {'version': '1', 'service_id': str(UUID(int=1883)), 'session_id': SESSION,
        'policy': contract.policy_for_selection(selected).to_dict(), 'limits': contract.limits(selected),
        'execute': True, 'profile': contract.PROFILE, 'case': selected}


def request(config, sequence=1, *, operation='execute', permit=None):
    value = {'version': '1', 'service_id': config['service_id'], 'session_id': config['session_id'],
        'sequence': sequence, 'operation': operation, 'action': contract.action(config['case']),
        'policy_digest': admission.digest(config['policy'])}
    if operation == 'redeem':
        value['permit'] = permit
    return value


def envelope(implementation='apache', config='A', case='O1'):
    selected = contract.selection(implementation, config, case)
    action = parse_action(contract.action(selected))
    policy = contract.policy_for_selection(selected)
    limits = contract.limits(selected)
    return {'mode': contract.PROFILE, 'selection': selected, 'identity': identity(implementation, config, case),
        'runtime': runtime(implementation, config, case), 'namespaces': {key: key + ':[200]' for key in HOST},
        'launch': {'schema_version': '1', 'mode': contract.PROFILE, 'execute': True,
            'session_id': SESSION, 'nonce': NONCE, 'sequence': 1,
            'action': action.to_dict(), 'action_digest': action.digest,
            'policy': policy.to_dict(), 'policy_digest': policy.digest,
            'limits': limits, 'limits_digest': admission.digest(limits), 'deadline': 150,
            'output_reserved_before': 0, 'output_reserved_after': limits['max_output_bytes'],
            'host_namespaces': HOST}}


def verify(value):
    raw = spec.encode(value)
    return consume_launch(raw, NONCE, hashlib.sha256(raw).hexdigest(), now=100)


def initial(implementation='apache'):
    config = configuration(implementation)
    config['owned_lab'] = identity(implementation)
    closure = base_runtime()
    closure['files'].append('/usr/bin/nsenter')
    closure['stock_http_runtime'] = runtime(implementation)
    return {'configuration': config, 'deadline': 160, 'runtime': closure,
        'audit_witness': {'version': '1', 'writer_id': str(UUID(int=1990)), 'device': 1, 'inode': 2},
        'approval_witness': {'version': '1', 'broker_id': str(UUID(int=1991)), 'device': 1, 'inode': 3}}


@pytest.mark.parametrize('implementation', ('nginx', 'apache'))
@pytest.mark.parametrize('config,case', spec.TRIALS)
def test_both_implementations_retain_exact_action_requests_and_limits(implementation, config, case):
    value = envelope(implementation, config, case)
    req, deadline, namespaces, runtime_hash = verify(value)
    assert req['selection'] == value['selection']
    assert req['parameters'] == spec.action(config, case)['parameters']
    assert deadline == 150 and namespaces == value['namespaces']
    assert (runtime_hash is None) == (case not in ('O5', 'O6'))
    selected = configuration(implementation, config, case)
    assert admission.configuration(selected) == selected
    assert launcher.request(request(selected), selected, 1).to_dict() == spec.action(config, case)


def test_policy_and_selection_bind_implementation_even_when_actions_identical():
    selections = [contract.selection(implementation, *pair) for implementation in ('nginx', 'apache') for pair in spec.TRIALS]
    assert len({row['selection_sha256'] for row in selections}) == 52
    policies = [contract.policy_for_selection(row) for row in selections]
    assert len({policy.digest for policy in policies}) == 52
    assert all(len(policy.policy_version) <= 64 for policy in policies)
    assert contract.action(contract.selection('nginx', 'A', 'O1')) == contract.action(contract.selection('apache', 'A', 'O1'))
    value = configuration()
    value['policy'] = contract.policy_for_selection(contract.selection('nginx', 'A', 'O1')).to_dict()
    with pytest.raises(ValueError, match='policy_binding_changed'):
        admission.configuration(value)


@pytest.mark.parametrize('fault', ('selection_implementation', 'owner_implementation', 'runtime_implementation',
    'diagnostic_profile', 'preparation_selection', 'outer_mode', 'inner_mode', 'runtime_hash',
    'owner_session', 'owner_runtime', 'policy', 'steps', 'deadline', 'namespace', 'sequence', 'execute'))
def test_recommitted_launch_cannot_swap_implementation_or_bypass_authority(fault):
    value = envelope()
    launch = value['launch']
    if fault == 'selection_implementation': value['selection'] = contract.selection('nginx', 'A', 'O1')
    elif fault == 'owner_implementation': value['identity']['implementation'] = 'nginx'
    elif fault == 'runtime_implementation': value['runtime'] = runtime('nginx')
    elif fault == 'diagnostic_profile': value['identity']['profile'] = 'stock_nginx_diagnostic_v1'
    elif fault == 'preparation_selection': value['selection'] = contract.preparation_selection(value['selection'])
    elif fault == 'outer_mode': value['mode'] = 'stock_nginx_diagnostic_v1'
    elif fault == 'inner_mode': launch['mode'] = 'stock_nginx_diagnostic_v1'
    elif fault == 'runtime_hash': value['runtime']['daemon']['files'][0]['sha256'] = 'b' * 64
    elif fault == 'owner_session': value['identity']['session_id'] = str(UUID(int=1999))
    elif fault == 'owner_runtime': value['identity']['daemon_runtime_sha256'] = 'b' * 64
    elif fault == 'policy': launch['policy'] = contract.policy_for_selection(contract.selection('nginx', 'A', 'O1')).to_dict()
    elif fault == 'steps': launch['limits']['max_steps'] = 2
    elif fault == 'deadline': launch['deadline'] = 161
    elif fault == 'namespace': value['namespaces']['net'] = HOST['net']
    elif fault == 'sequence': launch['sequence'] = 2
    else: launch['execute'] = False
    for field in ('action', 'policy', 'limits'): launch[field + '_digest'] = admission.digest(launch[field])
    with pytest.raises(ValueError): verify(value)


@pytest.mark.parametrize('implementation', ('nginx', 'apache'))
def test_both_independent_witnesses_and_production_tag_are_required(implementation):
    value = initial(implementation)
    for require in (True, False):
        value['configuration']['policy'] = contract.policy_for_selection(value['configuration']['case'], require_approval=require).to_dict()
        assert launcher.initial(value, 100) == value['configuration']
        for key in ('audit_witness', 'approval_witness'):
            changed = deepcopy(value); del changed[key]
            with pytest.raises(ValueError): launcher.initial(changed, 100)
    for tag in (None, 'launch-witness', 'stock-http-launch-preconditions', 'configurable-launch-preconditions'):
        with pytest.raises(ValueError): launcher.validate_runtime_tag(tag, value['configuration'], value['runtime'])
    launcher.validate_runtime_tag('stock-http-production-launch-preconditions', value['configuration'], value['runtime'])


def test_direct_host_backend_and_unwitnessed_launcher_cannot_execute():
    from recon_cockpit.secure_agent.stock_http_production_backend import AuthorizedStockHttpProductionBackend
    from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
    from recon_cockpit.secure_agent.isolation import IsolationUnavailable
    backend = object.__new__(AuthorizedStockHttpProductionBackend)
    with pytest.raises(IsolationUnavailable, match='witnessed'): backend.run(None, None)
    with pytest.raises(ValueError, match='isolated_audit_and_approval'): LinuxFixtureLauncher(backend)


def failed_result(implementation='apache'):
    value = diagnostic_failure()
    selected_identity = identity(implementation)
    value['backend'] = contract.BACKEND
    value['owned_lab']['identity'] = selected_identity
    value['stock_http_closure']['identity'] = selected_identity
    owner = value['stock_http_owner']['owner']
    owner['implementation'] = implementation
    uid = 0 if implementation == 'nginx' else 65534
    owner['daemon_namespace_identity'] = {'uid': uid, 'gid': uid, 'supplementary_groups': []}
    owner['private_transport'] = {'kind': 'unix_socket', 'listener_verified': True, 'descriptor': None}
    if implementation == 'apache':
        owner['private_transport'] = {'kind': 'namespace_tcp_descriptor', 'listener_verified': True,
            'descriptor': {'daemon_netns_cookie': 2, 'recorder_netns_cookie': 1, 'inode': 100,
                'unconnected_at_transfer': True, 'transferred_once': True, 'daemon_duplicate_closed': True,
                'connect_denied_in_daemon': True}}
    value['owned_lab']['owner_receipt_sha256'] = hashlib.sha256(spec.encode(value['stock_http_owner'])).hexdigest()
    return value


@pytest.mark.parametrize('implementation', ('nginx', 'apache'))
def test_result_preserves_failed_usefulness_with_transport_custody(implementation):
    value = failed_result(implementation)
    actual = contract.validate_result_context(value, identity(implementation), tool_id='configurable_http_headers_v1', execution_status='failed')
    assert actual['connection_count'] == 0 and value['tool_observation'] is None


@pytest.mark.parametrize('fault', ('implementation', 'identity_uid', 'identity_groups', 'transport_kind', 'listener',
    'cookie_same', 'cookie_bool', 'inode_zero', 'connected', 'repeated_transfer', 'duplicate_open', 'connect_allowed',
    'descriptor_extra', 'cleanup', 'owner_namespace', 'bounds', 'unarmed', 'unfinished', 'observation'))
def test_rehashed_owner_receipt_cannot_hide_transport_or_enforcement_failures(fault):
    value = failed_result()
    owner = value['stock_http_owner']['owner']
    descriptor = owner['private_transport']['descriptor']
    if fault == 'implementation': owner['implementation'] = 'nginx'
    elif fault == 'identity_uid': owner['daemon_namespace_identity']['uid'] = 0
    elif fault == 'identity_groups': owner['daemon_namespace_identity']['supplementary_groups'] = [0]
    elif fault == 'transport_kind': owner['private_transport']['kind'] = 'unix_socket'
    elif fault == 'listener': owner['private_transport']['listener_verified'] = 1
    elif fault == 'cookie_same': descriptor['daemon_netns_cookie'] = descriptor['recorder_netns_cookie']
    elif fault == 'cookie_bool': descriptor['daemon_netns_cookie'] = True
    elif fault == 'inode_zero': descriptor['inode'] = 0
    elif fault == 'connected': descriptor['unconnected_at_transfer'] = False
    elif fault == 'repeated_transfer': descriptor['transferred_once'] = False
    elif fault == 'duplicate_open': descriptor['daemon_duplicate_closed'] = False
    elif fault == 'connect_allowed': descriptor['connect_denied_in_daemon'] = False
    elif fault == 'descriptor_extra': descriptor['extra'] = True
    elif fault == 'cleanup': value['stock_http_closure']['processes_reaped'] = False
    elif fault == 'owner_namespace': owner['daemon_namespaces'] = owner['recorder_namespaces']
    elif fault == 'bounds': owner['daemon_bounds']['scratch_bytes'] *= 2
    elif fault == 'unarmed': value['stock_http_owner']['recorder']['armed'] = False
    elif fault == 'unfinished': value['stock_http_owner']['recorder'].update(finalized=False, terminal_reason='running')
    else: value['tool_observation'] = {'invented': True}
    value['owned_lab']['owner_receipt_sha256'] = hashlib.sha256(spec.encode(value['stock_http_owner'])).hexdigest()
    with pytest.raises(ValueError):
        contract.validate_result_context(value, identity(), tool_id='configurable_http_headers_v1', execution_status='failed')


@pytest.mark.parametrize('implementation', ('nginx', 'apache'))
def test_production_single_use_admission_never_refunds_or_replays(implementation):
    config = configuration(implementation)
    state = admission.AdmissionState({'configuration': config, 'deadline': 160}, clock=lambda: 100)
    granted = state.handle(request(config, operation='admit'))
    assert granted['reason'] is None
    assert granted['snapshot'] == {'executions_reserved': 1, 'output_bytes_reserved': 2048}
    assert state.handle(request(config, 2, operation='redeem', permit=granted['permit']))['reason'] is None
    assert state.handle(request(config, 3, operation='redeem', permit=granted['permit']))['reason'] == 'admission_unknown_or_replayed'
    assert state.handle(request(config, 4, operation='admit'))['reason'] == 'admission_step_limit'
    with pytest.raises(ValueError): launcher.request(request(config, 2), config, 2)


@pytest.mark.parametrize('implementation', ('nginx', 'apache'))
@pytest.mark.parametrize('field', ('max_steps', 'max_runtime_seconds', 'max_output_bytes'))
@pytest.mark.parametrize('change', (1, -1, True))
def test_production_exact_bounds_cannot_be_rewritten(implementation, field, change):
    value = configuration(implementation)
    value['limits'][field] = change if type(change) is bool else value['limits'][field] + change
    with pytest.raises(ValueError): admission.configuration(value)


@pytest.mark.parametrize('implementation', ('nginx', 'apache'))
@pytest.mark.parametrize('fault', ('target', 'port', 'path', 'method', 'action_id', 'rationale', 'timeout', 'output'))
def test_production_changed_action_is_denied_before_reservation(implementation, fault):
    config = configuration(implementation)
    value = request(config, operation='admit')
    action = value['action']
    if fault == 'target': action['target'] = '10.77.0.99'
    elif fault == 'port': action['parameters']['port'] = 8081
    elif fault == 'path': action['parameters']['path'] = '/private'
    elif fault == 'method': action['parameters']['method'] = 'HEAD'
    elif fault == 'action_id': action['action_id'] = str(UUID(int=1999))
    elif fault == 'rationale': action['rationale'] = 'different'
    elif fault == 'timeout': action['parameters']['timeout_seconds'] = 2
    else: action['parameters']['max_output_bytes'] = 1024
    state = admission.AdmissionState({'configuration': config, 'deadline': 160}, clock=lambda: 100)
    denied = state.handle(value)
    assert denied['reason'] in ('admission_policy_denied', 'admission_profile_denied')
    assert denied['snapshot'] == {'executions_reserved': 0, 'output_bytes_reserved': 0}
    with pytest.raises(ValueError): launcher.request({**value, 'operation': 'execute'}, config, 1)


def test_cross_profile_schemas_and_source_mounts_remain_closed():
    from recon_cockpit.secure_agent import stock_http_contract as diagnostic
    from recon_cockpit.secure_agent import stock_http_client_runtime as client
    production = contract.selection('apache', 'A', 'O1')
    old = diagnostic.selection('A', 'O1')
    with pytest.raises(ValueError): diagnostic.validate_selection(production)
    with pytest.raises(ValueError): contract.validate_selection(old)
    with pytest.raises(ValueError): contract.validate_runtime(runtime('nginx'), production)
    with pytest.raises(ValueError): diagnostic.validate_runtime(runtime('apache'), old)
    assert client.validate_client_runtime(runtime('apache')['client'], contract.client_selection(production)) is None
    mounts = contract.runtime_source_mounts(runtime(), production)
    assert ('/usr/sbin/apache2', '/usr/sbin/apache2') in mounts
    assert all(destination != '/tool/apache2' and not destination.startswith('/tool/modules/') for _, destination in mounts)
    assert not any(path in ('/etc', '/usr', '/usr/lib', '/etc/apache2') for pair in mounts for path in pair)


@pytest.mark.parametrize('field,bad', [('implementation', 'Apache'), ('implementation', '../apache'),
    ('implementation', None), ('configuration', 'external'), ('case', 'O7'), ('selection_sha256', '0' * 64)])
def test_finite_selection_rejects_unreviewed_or_relabelled_values(field, bad):
    value = contract.selection('apache', 'A', 'O1')
    value[field] = bad
    with pytest.raises(ValueError): contract.validate_selection(value)


@pytest.mark.parametrize('implementation', ('nginx', 'apache'))
def test_admission_actual_mount_closure_has_no_repository_import_fallback(tmp_path, monkeypatch, implementation):
    import shutil
    import subprocess
    import sys
    from pathlib import Path
    from recon_cockpit.secure_agent import admission_isolation
    monkeypatch.setattr(admission_isolation, '_trusted_program', lambda name: '/usr/bin/' + name)
    monkeypatch.setattr(admission_isolation, '_namespaces', lambda: dict(HOST))
    owner = admission_isolation.LinuxLaunchAdmission.__new__(admission_isolation.LinuxLaunchAdmission)
    owner._config = configuration(implementation)
    command = owner._command('/stdlib', [], 'a' * 64)
    for index, flag in enumerate(command):
        if flag == '--ro-bind' and command[index + 2].startswith('/app/'):
            destination = tmp_path / command[index + 2].removeprefix('/app/')
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(command[index + 1], destination)
    code = '''import importlib.util,json,sys
sys.path.insert(0,sys.argv[1])
from admission_runtime import launch_admission
entry=importlib.util.spec_from_file_location('admission_entry',sys.argv[1]+'/admission_runtime/admission_worker.py')
admission_worker=importlib.util.module_from_spec(entry)
entry.loader.exec_module(admission_worker)
value=json.loads(sys.argv[2])
assert launch_admission.configuration(value)==value
assert admission_worker.__file__.startswith(sys.argv[1])
print('closed-admission-ok')
'''
    result = subprocess.run([sys.executable, '-I', '-S', '-c', code, str(tmp_path), spec.encode(owner._config).decode()],
        capture_output=True, timeout=10, env={'LC_ALL': 'C'}, check=False)
    assert result.returncode == 0, result.stderr.decode('utf-8', 'replace')
    assert result.stdout == b'closed-admission-ok\n'


@pytest.mark.parametrize('implementation', ('nginx', 'apache'))
def test_launcher_actual_mount_closure_has_no_repository_import_fallback(tmp_path, monkeypatch, implementation):
    import shutil
    import subprocess
    import sys
    from recon_cockpit.secure_agent import launcher_isolation
    monkeypatch.setattr(launcher_isolation, '_trusted_program', lambda name: '/usr/bin/' + name)
    monkeypatch.setattr(launcher_isolation, '_namespaces', lambda: dict(HOST))
    owner = launcher_isolation.LinuxFixtureLauncher.__new__(launcher_isolation.LinuxFixtureLauncher)
    initial_value = initial(implementation)
    owner._config = initial_value['configuration']
    owner._witness_source = owner._approval_source = {}
    command = owner._command({'stdlib': '/stdlib'}, [], 'a' * 64)
    for index, flag in enumerate(command):
        if flag == '--ro-bind' and command[index + 2].startswith('/app/'):
            destination = tmp_path / command[index + 2].removeprefix('/app/')
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(command[index + 1], destination)
    code = '''import json,sys
sys.path.insert(0,sys.argv[1])
from recon_cockpit.secure_agent import launcher_worker,launcher_protocol
from recon_cockpit.secure_agent import stock_http_production_backend,stock_http_production_lab
value=json.loads(sys.argv[2])
assert launcher_protocol.initial(value,100)==value['configuration']
assert launcher_worker.__file__.startswith(sys.argv[1])
print('closed-launcher-ok')
'''
    result = subprocess.run([sys.executable, '-I', '-S', '-c', code, str(tmp_path), spec.encode(initial_value).decode()],
        capture_output=True, timeout=10, env={'LC_ALL': 'C'}, check=False)
    assert result.returncode == 0, result.stderr.decode('utf-8', 'replace')
    assert result.stdout == b'closed-launcher-ok\n'
