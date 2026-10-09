"""SMTP STARTTLS retains the existing OpenSSL authority and finite TLS closure."""

import hashlib
import resource
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_worker as worker
from test_secure_network_tools_runtime import envelope, manifest, recommit, verify
from test_secure_network_tools_runtime import test_fresh_commitments_do_not_bypass_fixed_authority as _authority_fault


def test_all_22_accepted_runtime_profiles_remain_byte_identical():
    # Independently captured from merged PR60 aa65bff before C7 runtime edits.
    selected = {tool: [executable, runtime.FIXED_ARGV[tool], runtime.execution_environment(tool),
        [(source, destination, raw.hex()) for source, destination, raw in runtime.compiled_files(tool)]]
        for tool, executable in runtime.EXECUTABLES.items() if tool not in (runtime.SMTP_TLS, runtime.LDAP_TLS, runtime.FTP_TLS, runtime.DIG_NSID, runtime.DIG_AXFR, runtime.HTTP_OPTIONS, runtime.SNMP_NEXT, runtime.SSH_ALGORITHMS, runtime.TLS_CERTIFICATE, runtime.NUCLEI, runtime.NUCLEI_GIT, runtime.DIG_MX)}
    assert len(selected) == 22
    assert hashlib.sha256(runtime.encode(selected)).hexdigest() == 'd8628a0f2e5d7fc962f7d8c5a93968180e2b908979d0c8a567455f15e29c6ee2'


def test_fixed_smtp_client_adds_only_starttls_and_literal_ehlo_name():
    assert runtime.EXECUTABLES[runtime.SMTP_TLS] == '/usr/bin/openssl'
    argv = runtime.FIXED_ARGV[runtime.SMTP_TLS]
    assert argv == runtime.FIXED_ARGV[runtime.OPENSSL] + ('-starttls', 'smtp', '-name', 'harbordesk.test')
    assert argv == ('/tool/openssl', 's_client', '-4', '-connect', '127.0.0.1:8080',
        '-servername', 'harbordesk.test', '-verify_hostname', 'harbordesk.test', '-verify_return_error',
        '-CAfile', '/tool/data/fixture-ca.pem', '-no-CApath', '-no-CAstore', '-tls1_3',
        '-ciphersuites', 'TLS_AES_256_GCM_SHA384', '-brief', '-no_ign_eof',
        '-starttls', 'smtp', '-name', 'harbordesk.test')
    assert not {'-reconnect', '-cert', '-key', '-proxy', '-sess_out', '-keylogfile', '-provider',
        '-engine', '-ign_eof', '-pass', '-early_data', '-crlf'} & set(argv)


def test_mail_credentials_and_host_tls_configuration_cannot_enter_runtime(monkeypatch):
    for name in ('HOME', 'MAIL', 'EMAIL', 'SMTP_PASSWORD', 'OPENSSL_CONF', 'OPENSSL_MODULES',
            'SSL_CERT_FILE', 'SSL_CERT_DIR', 'LD_PRELOAD', 'http_proxy'):
        monkeypatch.setenv(name, '/private/injected')
    assert runtime.execution_environment(runtime.SMTP_TLS) == {
        'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null', 'MALLOC_ARENA_MAX': '1'}
    compiled = runtime.compiled_files(runtime.SMTP_TLS)
    assert compiled == runtime.compiled_files(runtime.OPENSSL)
    assert len(compiled) == 1 and compiled[0][:2] == ('compiled:fixture-ca', '/tool/data/fixture-ca.pem')
    assert b'PRIVATE KEY' not in compiled[0][2]
    permissions = worker._landlock_permissions(manifest(runtime.SMTP_TLS))
    assert permissions == worker._landlock_permissions(manifest(runtime.OPENSSL))
    assert permissions['/tool/data/fixture-ca.pem'] == 4
    assert not any(path.startswith(('/etc', '/home', '/root', '/var')) for path in permissions)
    assert '/usr/bin/python3' not in permissions


@pytest.mark.parametrize('path', ['/etc/ssl/openssl.cnf', '/etc/ssl/certs/host-ca.pem',
    '/root/.netrc', '/root/.msmtprc', '/tool/data/client.key', '/tool/data/client.crt', '/tmp/credential'])
def test_manifest_refuses_mail_credentials_host_trust_and_unreviewed_configuration(path):
    value = manifest(runtime.SMTP_TLS)
    value['files'].append({'source': path, 'destination': path, 'size': 1, 'sha256': 'a' * 64})
    value['files'].sort(key=lambda row: row['destination'])
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize('fault', ['ca_source', 'ca_hash', 'ca_size', 'no_ca', 'profile', 'interpreter', 'cap'])
def test_pinned_public_ca_cannot_be_replaced_or_closure_expanded(fault):
    value = manifest(runtime.SMTP_TLS)
    assert runtime.validate_manifest(value, tool_id=runtime.SMTP_TLS) == value
    ca = next(row for row in value['files'] if row['source'].startswith('compiled:'))
    if fault == 'ca_source': ca['source'] = '/tmp/replacement.pem'
    elif fault == 'ca_hash': ca['sha256'] = 'a' * 64
    elif fault == 'ca_size': ca['size'] += 1
    elif fault == 'no_ca': value['files'].remove(ca)
    elif fault == 'profile': value['profile'] = runtime.SMB_PROFILE
    elif fault == 'interpreter': value['interpreter'] = '/usr/bin/python3'
    else: value['files'][0]['size'] = runtime.MAX_FILE_BYTES + 1
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


def test_public_ca_snapshot_never_exposes_owner_fixture_or_private_key(monkeypatch):
    value, seen = manifest(runtime.SMTP_TLS), []
    monkeypatch.setattr(runtime, 'sealed_snapshots', lambda *args, **kwargs: seen.append((args, kwargs)) or [])
    control = object()
    assert runtime._snapshot(value, control) == []
    source, _, raw = runtime.compiled_files(runtime.SMTP_TLS)[0]
    assert seen == [((value, source, raw, control), {})]
    monkeypatch.setattr(runtime, '_trusted_program', lambda name: '/usr/bin/' + name)
    argv = runtime._command(SimpleNamespace(_namespace_fds=(10, 11)),
        ('/usr/lib/python3.13', [('/usr/bin/python3', '/usr/bin/python3')]),
        value, [20, 21, 22], 'a' * 64, 'b' * 64)
    assert argv.count('--ro-bind-data') == 3
    assert 'CAP_NET_ADMIN' not in argv and 'CAP_NET_BIND_SERVICE' not in argv
    assert not any('smtp_tls_fixture' in arg or 'web_tools_tls_fixture' in arg for arg in argv)
    assert all(not source.startswith('compiled:') for source, _ in runtime.runtime_source_mounts(value))


@pytest.mark.parametrize('other_case', ['openssl-ok', 'postgresql-tls-ok', 'mysql-tls-ok', 'smtp-ok'])
def test_shared_openssl_and_smtp_prefix_do_not_allow_cross_profile_authority(other_case):
    value, other = envelope('smtp-tls-ok'), envelope(other_case)
    value['runtime'] = other['runtime']
    with pytest.raises(ValueError):
        verify(value)
    value['launch']['action'] = other['launch']['action']
    recommit(value)
    with pytest.raises(ValueError):
        verify(value)


@pytest.mark.parametrize('case', fixture.SMTP_TLS_CASES)
@pytest.mark.parametrize('fault', ['mode', 'inner_mode', 'identity', 'manifest', 'namespace',
    'deadline', 'sequence', 'reservation', 'policy', 'action', 'limit'])
def test_fresh_launch_commitments_cannot_bypass_smtp_tls_authority(case, fault):
    _authority_fault(case, fault)


def test_smtp_tls_has_no_thread_exception_and_keeps_existing_resource_caps(monkeypatch):
    seen, limits = [], {}
    monkeypatch.setattr(worker.common, 'syscall_filter', lambda **kwargs: seen.append(kwargs))
    worker.syscall_filter(runtime.SMTP_TLS)
    assert seen == [{'allow_threads': False}]
    monkeypatch.setattr(worker.resource, 'getrlimit', lambda _: (resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, 'setrlimit', lambda key, value: limits.update({key: value}))
    worker._limits(runtime.SMTP_TLS)
    assert limits[resource.RLIMIT_NPROC] == (1, 1)
    assert limits[resource.RLIMIT_AS] == (256 * 1024 * 1024,) * 2
    assert limits[resource.RLIMIT_FSIZE] == (0, 0)
