"""Peer certificate capture keeps dedicated fixture trust separate from prior TLS profiles."""

import base64
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import resource
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_worker as worker
from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import tool_adapters as adapters
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.models import TLSCertificateParameters, ValidationError, parse_action, parse_policy
from test_secure_network_tools_runtime import envelope, manifest, recommit, verify
from test_secure_network_tools_runtime import test_fresh_commitments_do_not_bypass_fixed_authority as _authority_fault


def test_all_30_accepted_runtime_profiles_remain_byte_identical():
    # Independently captured from merged PR68 a6f11b7 before C15 runtime edits.
    selected = {tool: [executable, runtime.FIXED_ARGV[tool], runtime.execution_environment(tool),
        [(source, destination, raw.hex()) for source, destination, raw in runtime.compiled_files(tool)]]
        for tool, executable in runtime.EXECUTABLES.items() if tool not in (runtime.TLS_CERTIFICATE, runtime.NUCLEI, runtime.NUCLEI_GIT)}
    assert len(selected) == 30
    assert hashlib.sha256(runtime.encode(selected)).hexdigest() == 'e95562a6d07d64a67e31a2fc621da7101e3132343012c850d5c1ae474d6dc655'


def test_all_39_accepted_adapters_remain_byte_identical():
    selected = {tool: adapter.to_dict() for tool, adapter in adapters.ADAPTERS.items()
                if tool not in (runtime.TLS_CERTIFICATE, runtime.NUCLEI, runtime.NUCLEI_GIT)}
    assert len(selected) == 39
    assert hashlib.sha256(runtime.encode(selected)).hexdigest() == (
        '97301638f860f2d81fe9f01c69ed8a45bacf4a9010bb2f325161a86fa66975b5')


def test_certificate_parameters_are_typed_immutable_and_have_distinct_policy_authority():
    from test_secure_network_tools_runtime import policy
    action = parse_action(contract.action(fixture.TLS_CERTIFICATE_CASES[0]))
    assert type(action.parameters) is TLSCertificateParameters
    assert action.parameters.to_dict() == dict(adapters.TLS_CERTIFICATE_PARAMETERS)
    with pytest.raises(FrozenInstanceError):
        action.parameters.port = 443
    descriptor = adapters.get_adapter(runtime.TLS_CERTIFICATE).to_dict()
    assert descriptor['parameters']['additionalProperties'] is False
    assert descriptor['parameters']['required'] == ['port', 'timeout_seconds', 'max_output_bytes']
    assert descriptor['parser_version'] == 'openssl-peer-certificate-v1'
    assert descriptor['approval'] == 'operator_policy'
    configured = policy().to_dict()
    configured.update(allowed_tools=[runtime.TLS_CERTIFICATE], allowed_methods=[])
    assert parse_policy(configured).evaluate(action).decision == 'approval_required'
    assert parse_policy(configured).evaluate(parse_action(contract.action('openssl-ok'))).reasons == ('tool_not_allowed',)
    configured['allowed_tools'] = [runtime.OPENSSL]
    assert parse_policy(configured).evaluate(action).reasons == ('tool_not_allowed',)


@pytest.mark.parametrize('field', ['servername', 'verify_hostname', 'ca_file', 'ca_path', 'ca_store',
    'client_certificate', 'private_key', 'password', 'credentials', 'trust', 'verify', 'alpn',
    'cipher', 'protocol', 'starttls', 'session', 'early_data', 'application_data', 'stdin',
    'keylog', 'output_path', 'provider', 'engine', 'proxy', 'argv', 'command', 'environment'])
def test_proposals_cannot_select_tls_options_trust_credentials_or_application_data(field):
    action = contract.action(fixture.TLS_CERTIFICATE_CASES[0])
    action['parameters'][field] = 'untrusted'
    with pytest.raises(ValidationError, match='unknown_parameters_fields'):
        parse_action(action)


@pytest.mark.parametrize('field,value', [('port', True), ('timeout_seconds', 0),
    ('max_output_bytes', False), ('port', 65536), ('timeout_seconds', 31), ('max_output_bytes', 65537)])
def test_parameter_types_and_syntactic_bounds_are_closed(field, value):
    action = contract.action(fixture.TLS_CERTIFICATE_CASES[0])
    action['parameters'][field] = value
    with pytest.raises(ValidationError):
        parse_action(action)


def test_fixed_certificate_client_keeps_verified_tls_and_only_changes_capture_flags():
    assert runtime.EXECUTABLES[runtime.TLS_CERTIFICATE] == '/usr/bin/openssl'
    argv = runtime.FIXED_ARGV[runtime.TLS_CERTIFICATE]
    assert argv == tuple(arg for arg in runtime.FIXED_ARGV[runtime.OPENSSL] if arg != '-brief') + (
        '-showcerts', '-nameopt', 'RFC2253', '-verify_quiet', '-no_ticket')
    assert argv == ('/tool/openssl', 's_client', '-4', '-connect', '127.0.0.1:8080',
        '-servername', 'harbordesk.test', '-verify_hostname', 'harbordesk.test', '-verify_return_error',
        '-CAfile', '/tool/data/fixture-ca.pem', '-no-CApath', '-no-CAstore', '-tls1_3',
        '-ciphersuites', 'TLS_AES_256_GCM_SHA384', '-no_ign_eof',
        '-showcerts', '-nameopt', 'RFC2253', '-verify_quiet', '-no_ticket')
    assert not {'-brief', '-reconnect', '-cert', '-key', '-proxy', '-sess_in', '-sess_out', '-keylogfile',
        '-provider', '-engine', '-ign_eof', '-pass', '-early_data', '-crlf', '-starttls',
        '-no_check_time', '-partial_chain', '-crl_download', '-status'} & set(argv)


def test_client_credentials_and_host_tls_configuration_cannot_enter_runtime(monkeypatch):
    for name in ('HOME', 'SSLKEYLOGFILE', 'OPENSSL_CONF', 'OPENSSL_MODULES',
            'SSL_CERT_FILE', 'SSL_CERT_DIR', 'LD_PRELOAD', 'http_proxy', 'https_proxy'):
        monkeypatch.setenv(name, '/private/injected')
    assert runtime.execution_environment(runtime.TLS_CERTIFICATE) == {
        'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null', 'MALLOC_ARENA_MAX': '1'}
    compiled = runtime.compiled_files(runtime.TLS_CERTIFICATE)
    assert compiled != runtime.compiled_files(runtime.OPENSSL)
    assert compiled[0][2] == fixture.TLS_CERTIFICATE_CA_PEM != fixture.CA_PEM
    assert len(compiled) == 1 and compiled[0][:2] == ('compiled:fixture-ca', '/tool/data/fixture-ca.pem')
    assert b'PRIVATE KEY' not in compiled[0][2]
    permissions = worker._landlock_permissions(manifest(runtime.TLS_CERTIFICATE))
    assert permissions == worker._landlock_permissions(manifest(runtime.OPENSSL))
    assert permissions['/tool/data/fixture-ca.pem'] == 4
    assert not any(path.startswith(('/etc', '/home', '/root', '/var')) for path in permissions)
    assert '/usr/bin/python3' not in permissions


@pytest.mark.parametrize('path', ['/etc/ssl/openssl.cnf', '/etc/ssl/certs/host-ca.pem',
    '/root/.netrc', '/etc/ssl/certs', '/tool/data/client.key', '/tool/data/client.crt', '/tmp/credential'])
def test_manifest_refuses_client_credentials_host_trust_and_unreviewed_configuration(path):
    value = manifest(runtime.TLS_CERTIFICATE)
    value['files'].append({'source': path, 'destination': path, 'size': 1, 'sha256': 'a' * 64})
    value['files'].sort(key=lambda row: row['destination'])
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize('fault', ['ca_source', 'ca_hash', 'ca_size', 'legacy_ca', 'no_ca', 'profile', 'interpreter', 'cap'])
def test_pinned_public_ca_cannot_be_replaced_or_closure_expanded(fault):
    value = manifest(runtime.TLS_CERTIFICATE)
    assert runtime.validate_manifest(value, tool_id=runtime.TLS_CERTIFICATE) == value
    ca = next(row for row in value['files'] if row['source'].startswith('compiled:'))
    if fault == 'ca_source': ca['source'] = '/tmp/replacement.pem'
    elif fault == 'ca_hash': ca['sha256'] = 'a' * 64
    elif fault == 'ca_size': ca['size'] += 1
    elif fault == 'legacy_ca':
        old = runtime.compiled_files(runtime.OPENSSL)[0][2]
        ca.update(size=len(old), sha256=hashlib.sha256(old).hexdigest())
    elif fault == 'no_ca': value['files'].remove(ca)
    elif fault == 'profile': value['profile'] = runtime.SMB_PROFILE
    elif fault == 'interpreter': value['interpreter'] = '/usr/bin/python3'
    else: value['files'][0]['size'] = runtime.MAX_FILE_BYTES + 1
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


def test_public_ca_snapshot_never_exposes_owner_fixture_or_private_key(monkeypatch):
    value, seen = manifest(runtime.TLS_CERTIFICATE), []
    monkeypatch.setattr(runtime, 'sealed_snapshots', lambda *args, **kwargs: seen.append((args, kwargs)) or [])
    control = object()
    assert runtime._snapshot(value, control) == []
    source, _, raw = runtime.compiled_files(runtime.TLS_CERTIFICATE)[0]
    assert seen == [((value, source, raw, control), {})]
    monkeypatch.setattr(runtime, '_trusted_program', lambda name: '/usr/bin/' + name)
    argv = runtime._command(SimpleNamespace(_namespace_fds=(10, 11)),
        ('/usr/lib/python3.13', [('/usr/bin/python3', '/usr/bin/python3')]),
        value, [20, 21, 22], 'a' * 64, 'b' * 64)
    assert argv.count('--ro-bind-data') == 3
    assert 'CAP_NET_ADMIN' not in argv and 'CAP_NET_BIND_SERVICE' not in argv
    assert not any('tls_certificate_fixture' in arg or 'tls_certificate_material' in arg
                   or 'web_tools_tls_fixture' in arg for arg in argv)
    assert all(not source.startswith('compiled:') for source, _ in runtime.runtime_source_mounts(value))


@pytest.mark.parametrize('other_case', ['openssl-ok', 'postgresql-tls-ok', 'mysql-tls-ok', 'smtp-tls-ok', 'ldap-tls-ok', 'ftp-tls-ok'])
@pytest.mark.parametrize('reverse', [False, True])
def test_shared_openssl_does_not_allow_cross_profile_authority(other_case, reverse):
    cases = (fixture.TLS_CERTIFICATE_CASES[0], other_case)
    if reverse:
        cases = cases[::-1]
    value, other = (envelope(case) for case in cases)
    value['runtime'] = other['runtime']
    with pytest.raises(ValueError):
        verify(value)
    value['launch']['action'] = other['launch']['action']
    recommit(value)
    with pytest.raises(ValueError):
        verify(value)


@pytest.mark.parametrize('reverse', [False, True])
def test_relabelling_an_openssl_runtime_cannot_substitute_the_other_profiles_ca(reverse):
    tools = (runtime.TLS_CERTIFICATE, runtime.OPENSSL)
    if reverse:
        tools = tools[::-1]
    candidate = deepcopy(manifest(tools[0]))
    candidate['tool_id'] = tools[1]
    with pytest.raises(ValueError):
        runtime.manifest_digest(candidate)


@pytest.mark.parametrize('case', fixture.TLS_CERTIFICATE_CASES)
@pytest.mark.parametrize('fault', ['mode', 'inner_mode', 'identity', 'manifest', 'namespace',
    'deadline', 'sequence', 'reservation', 'policy', 'action', 'limit'])
def test_fresh_launch_commitments_cannot_bypass_tls_certificate_authority(case, fault):
    _authority_fault(case, fault)


def test_tls_certificate_has_no_thread_exception_and_keeps_existing_resource_caps(monkeypatch):
    seen, limits = [], {}
    monkeypatch.setattr(worker.common, 'syscall_filter', lambda **kwargs: seen.append(kwargs))
    worker.syscall_filter(runtime.TLS_CERTIFICATE)
    assert seen == [{'allow_threads': False}]
    monkeypatch.setattr(worker.resource, 'getrlimit', lambda _: (resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, 'setrlimit', lambda key, value: limits.update({key: value}))
    worker._limits(runtime.TLS_CERTIFICATE)
    assert limits[resource.RLIMIT_NPROC] == (1, 1)
    assert limits[resource.RLIMIT_AS] == (256 * 1024 * 1024,) * 2
    assert limits[resource.RLIMIT_FSIZE] == (0, 0)
    assert limits[resource.RLIMIT_CPU] == (5, 5)
    assert limits[resource.RLIMIT_NOFILE] == (64, 64)
    assert limits[resource.RLIMIT_CORE] == (0, 0)
    monkeypatch.setattr(worker.resource, 'getrlimit', lambda _: (2, 2))
    worker._limits(runtime.TLS_CERTIFICATE)
    assert set(limits.values()) == {(0, 0), (1, 1), (2, 2)}


@pytest.mark.parametrize('code,reason,expected', [(0, None, 'succeeded'), (1, None, 'failed'),
    (-15, 'timeout', 'timeout'), (-15, 'output_limit', 'output_limit')])
def test_certificate_capture_keeps_failure_bounds_and_raw_channels_without_promoting_metadata(
        monkeypatch, code, reason, expected):
    monkeypatch.setattr(runtime, 'sys', SimpleNamespace(platform='linux'))
    launch = envelope(fixture.TLS_CERTIFICATE_CASES[0])
    selected = launch.pop('runtime')
    monkeypatch.setattr(runtime, '_snapshot', lambda *_: [])
    monkeypatch.setattr(runtime, '_command', lambda *_: ['fixed-worker'])
    stdout, stderr = b'untrusted certificate transcript', b'untrusted TLS diagnostic'
    def capture(argv, raw, timeout, maximum, **kwargs):
        assert argv == ['fixed-worker'] and 0 < timeout <= 5
        prefix = runtime.READY_PREFIX + hashlib.sha256(raw).hexdigest().encode() + b'\n'
        assert maximum == 8192 + len(prefix)
        return code, stdout, prefix + stderr, reason
    monkeypatch.setattr(runtime, '_capture_bounded', capture)
    lab = SimpleNamespace(_namespace_fds=(10, 11), _check=lambda *_: None, _verify_pins=lambda: None)
    result = runtime.run_network_tool_owned(lab=lab, launch=launch,
        control=ExecutionControl(time.monotonic() + 20), manifest=selected,
        closure={'stdlib': '/usr/lib/python3.13', 'files': [], 'network_tools_runtime': selected})
    assert result['status'] == expected and result['tool_observation'] is None
    assert result['truncated'] is (reason == 'output_limit')
    assert base64.b64decode(result['raw_output_base64']) == stdout
    assert base64.b64decode(result['raw_stderr_base64']) == stderr
    assert result['provenance']['runtime_manifest']['tool_id'] == runtime.TLS_CERTIFICATE
    assert result['provenance']['parser_version'] == 'openssl-peer-certificate-v1'
    assert result['provenance']['exit_code'] == code and result['provenance']['stop_reason'] == reason
