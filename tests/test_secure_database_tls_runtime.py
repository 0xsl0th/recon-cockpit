"""C2 reuses the pinned TLS runtime without adding database-session authority."""

import base64
import hashlib
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_worker as worker
from recon_cockpit.secure_agent.execution import ExecutionControl
from test_secure_network_tools_runtime import envelope, manifest, recommit, verify


TOOLS = (runtime.POSTGRESQL_TLS, runtime.MYSQL_TLS)
CASES = ('postgresql-tls-ok', 'mysql-tls-ok')


def test_all_accepted_runtime_contracts_are_unchanged():
    # Captured from accepted main 9786a6b, including C1's two profiles.
    selected = {tool: [executable, runtime.FIXED_ARGV[tool], runtime.execution_environment(tool),
        [(source, destination, raw.hex()) for source, destination, raw in runtime.compiled_files(tool)]]
        for tool, executable in runtime.EXECUTABLES.items() if tool not in (*TOOLS, runtime.WHATWEB, runtime.DIG_SRV, runtime.RDP, runtime.SMB2, runtime.SMTP_TLS, runtime.LDAP_TLS, runtime.FTP_TLS, runtime.DIG_NSID, runtime.DIG_AXFR, runtime.HTTP_OPTIONS, runtime.SNMP_NEXT, runtime.SSH_ALGORITHMS)}
    assert len(selected) == 16
    assert hashlib.sha256(runtime.encode(selected)).hexdigest() == 'a3a3f7747ace8e12b6c9a3691fb1ab3749174b8c5326acff23fd2dec7b31201a'


@pytest.mark.parametrize('tool,protocol', [(runtime.POSTGRESQL_TLS, 'postgres'), (runtime.MYSQL_TLS, 'mysql')])
def test_fixed_client_adds_only_the_reviewed_wire_preface_to_existing_verified_tls(tool, protocol):
    assert runtime.EXECUTABLES[tool] == '/usr/bin/openssl'
    assert runtime.FIXED_ARGV[tool] == runtime.FIXED_ARGV[runtime.OPENSSL] + ('-starttls', protocol)
    argv = runtime.FIXED_ARGV[tool]
    assert argv == ('/tool/openssl', 's_client', '-4', '-connect', '127.0.0.1:8080',
        '-servername', 'harbordesk.test', '-verify_hostname', 'harbordesk.test', '-verify_return_error',
        '-CAfile', '/tool/data/fixture-ca.pem', '-no-CApath', '-no-CAstore', '-tls1_3',
        '-ciphersuites', 'TLS_AES_256_GCM_SHA384', '-brief', '-no_ign_eof', '-starttls', protocol)
    assert not {'-reconnect', '-cert', '-key', '-proxy', '-sess_out', '-keylogfile', '-provider',
                '-engine', '-ign_eof', '-pass', '-name', '-early_data'} & set(argv)


@pytest.mark.parametrize('tool', TOOLS)
def test_runtime_cannot_inherit_database_credentials_or_host_tls_configuration(monkeypatch, tool):
    injected = {'HOME': '/private', 'PGHOST': 'remote', 'PGUSER': 'private', 'PGPASSWORD': 'private',
        'PGPASSFILE': '/private/pgpass', 'PGSERVICEFILE': '/private/pg_service.conf',
        'MYSQL_PWD': 'private', 'MYSQL_HOME': '/private', 'OPENSSL_CONF': '/private/tls.conf',
        'OPENSSL_MODULES': '/private/modules', 'SSL_CERT_FILE': '/private/root.pem',
        'SSL_CERT_DIR': '/private/roots', 'LD_PRELOAD': '/private/plugin.so'}
    for key, value in injected.items():
        monkeypatch.setenv(key, value)
    assert runtime.execution_environment(tool) == {
        'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null', 'MALLOC_ARENA_MAX': '1'}
    compiled = runtime.compiled_files(tool)
    assert compiled == runtime.compiled_files(runtime.OPENSSL)
    assert len(compiled) == 1 and compiled[0][:2] == ('compiled:fixture-ca', '/tool/data/fixture-ca.pem')
    assert b'PRIVATE KEY' not in compiled[0][2]
    permissions = worker._landlock_permissions(manifest(tool))
    assert permissions == worker._landlock_permissions(manifest(runtime.OPENSSL))
    assert permissions['/tool/data/fixture-ca.pem'] == 4
    assert '/usr/bin/python3' not in permissions
    assert not any(path.startswith(('/etc', '/home', '/root', '/var')) for path in permissions)


@pytest.mark.parametrize('tool', TOOLS)
@pytest.mark.parametrize('path', ['/etc/ssl/openssl.cnf', '/etc/ssl/certs/host-ca.pem', '/root/.pgpass',
    '/root/.my.cnf', '/tool/data/client.key', '/tool/data/client.crt', '/tmp/credential'])
def test_manifest_refuses_database_credentials_host_trust_and_unreviewed_configuration(tool, path):
    value = manifest(tool)
    value['files'].append({'source': path, 'destination': path, 'size': 1, 'sha256': 'a' * 64})
    value['files'].sort(key=lambda row: row['destination'])
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize('tool', TOOLS)
@pytest.mark.parametrize('fault', ['ca_source', 'ca_hash', 'ca_size', 'no_ca', 'profile', 'interpreter', 'cap'])
def test_pinned_public_ca_cannot_be_replaced_or_runtime_expanded(tool, fault):
    value = manifest(tool)
    assert runtime.validate_manifest(value, tool_id=tool) == value
    ca = next(row for row in value['files'] if row['source'].startswith('compiled:'))
    if fault == 'ca_source':
        ca['source'] = '/tmp/replacement.pem'
    elif fault == 'ca_hash':
        ca['sha256'] = 'a' * 64
    elif fault == 'ca_size':
        ca['size'] += 1
    elif fault == 'no_ca':
        value['files'].remove(ca)
    elif fault == 'profile':
        value['profile'] = runtime.SMB_PROFILE
    elif fault == 'interpreter':
        value['interpreter'] = '/usr/bin/python3'
    else:
        value['files'][0]['size'] = runtime.MAX_FILE_BYTES + 1
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize('tool', TOOLS)
def test_ca_snapshot_uses_compiled_bytes_and_never_mounts_owner_private_key(monkeypatch, tool):
    value, seen = manifest(tool), []
    monkeypatch.setattr(runtime, 'sealed_snapshots', lambda *args, **kwargs: seen.append((args, kwargs)) or [])
    control = object()
    assert runtime._snapshot(value, control) == []
    source, _, raw = runtime.compiled_files(tool)[0]
    assert seen == [((value, source, raw, control), {})]
    monkeypatch.setattr(runtime, '_trusted_program', lambda name: '/usr/bin/' + name)
    argv = runtime._command(SimpleNamespace(_namespace_fds=(10, 11)),
        ('/usr/lib/python3.13', [('/usr/bin/python3', '/usr/bin/python3')]),
        value, [20, 21, 22], 'a' * 64, 'b' * 64)
    assert argv.count('--ro-bind-data') == 3
    assert 'CAP_NET_ADMIN' not in argv and 'CAP_NET_BIND_SERVICE' not in argv
    assert not any('database_tls_fixture' in arg or 'web_tools_tls_fixture' in arg for arg in argv)
    assert all(not source.startswith('compiled:') for source, _ in runtime.runtime_source_mounts(value))


@pytest.mark.parametrize('case', CASES)
@pytest.mark.parametrize('other_case', ['openssl-ok', 'postgresql-tls-ok', 'mysql-tls-ok'])
def test_sharing_openssl_does_not_allow_cross_profile_launch_authority(case, other_case):
    if case == other_case:
        return
    value = envelope(case)
    other = envelope(other_case)
    # Identical executable/CA bytes cannot substitute a different protocol's
    # manifest or action into the case-bound independently consumed launch.
    value['runtime'] = other['runtime']
    with pytest.raises(ValueError):
        verify(value)
    value['launch']['action'] = other['launch']['action']
    recommit(value)
    with pytest.raises(ValueError):
        verify(value)


@pytest.mark.parametrize('case', CASES)
@pytest.mark.parametrize('code,reason,expected', [(0, None, 'succeeded'), (1, None, 'failed'),
    (-15, 'timeout', 'timeout'), (-15, 'output_limit', 'output_limit')])
def test_tls_capture_preserves_exit_failure_timeout_and_both_raw_channels(monkeypatch, case, code, reason, expected):
    monkeypatch.setattr(runtime, 'sys', SimpleNamespace(platform='linux'))
    launch = envelope(case)
    selected = launch.pop('runtime')
    monkeypatch.setattr(runtime, '_snapshot', lambda *_: [])
    monkeypatch.setattr(runtime, '_command', lambda *_: ['fixed-worker'])
    stdout, stderr = b'untrusted protocol data', b'untrusted TLS diagnostics'
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
    assert result['provenance']['runtime_manifest']['tool_id'] == selected['tool_id']
    assert result['provenance']['parser_version'] == ('postgresql-tls-brief-v1'
        if case.startswith('postgresql-') else 'mysql-tls-brief-v1')
    assert result['provenance']['exit_code'] == code
    assert result['provenance']['stop_reason'] == reason


@pytest.mark.parametrize('tool', TOOLS)
def test_c2_profiles_are_supported_by_both_secure_backends(tool):
    from recon_cockpit.secure_agent.network_tools_backend import (
        AuthorizedNetworkToolsBackend, ConfinedNetworkToolsBackend)
    assert tool in AuthorizedNetworkToolsBackend.supported_tools
    assert tool in ConfinedNetworkToolsBackend.supported_tools
