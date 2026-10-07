"""Portable checks for the finite Ruby closure and WhatWeb execution authority."""

import hashlib
from pathlib import Path
import resource
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_whatweb_runtime as whatweb
from recon_cockpit.secure_agent import network_tools_worker as worker
from recon_cockpit.secure_agent.isolation import IsolationUnavailable


def manifest():
    """Synthetic bytes for portable authority tests; never a native receipt."""
    compiled = {source: raw for source, _, raw in whatweb.COMPILED}
    files = []
    for source, destination in whatweb.fixed_entries():
        raw = compiled.get(source, b"data")
        files.append({"source": source, "destination": destination, "size": len(raw),
                      "sha256": hashlib.sha256(raw).hexdigest()})
    return whatweb.compact_manifest({"version": "1", "profile": whatweb.PROFILE,
        "tool_id": whatweb.TOOL_ID, "executable": whatweb.DESTINATION,
        "interpreter": "/lib64/ld-linux-x86-64.so.2",
        "files": sorted(files, key=lambda row: row["destination"])})


def test_every_accepted_pre_c3_runtime_contract_remains_byte_identical():
    selected = {tool: [executable, runtime.FIXED_ARGV[tool], runtime.execution_environment(tool),
        [(source, destination, raw.hex()) for source, destination, raw in runtime.compiled_files(tool)]]
        for tool, executable in runtime.EXECUTABLES.items() if tool != runtime.WHATWEB}
    assert len(selected) == 18
    # Independently captured from accepted main 9603a54 before C3 changes.
    assert hashlib.sha256(runtime.encode(selected)).hexdigest() == '0436d2a36d3c85ca6cc07c6bd1257aec78a41b7e2474d6db0d20103b291db94e'


def test_compact_manifest_roundtrips_complete_fixed_distribution_closure():
    value = manifest()
    assert runtime.validate_manifest(value, tool_id=runtime.WHATWEB) == value
    files = runtime.runtime_files(value)
    assert len(files) == len(set(whatweb.fixed_entries())) == 180
    assert {(row['source'], row['destination']) for row in files} == set(whatweb.fixed_entries())
    assert all(type(row) is list and len(row) == 3 for row in value['files'])
    assert whatweb.compact_manifest({**value, 'files': files}) == value
    assert len(runtime.encode(value)) < whatweb.MAX_MANIFEST_BYTES
    assert not any(source.startswith('compiled:') for source, _ in runtime.runtime_source_mounts(value))


@pytest.mark.parametrize('field,value', [('profile', runtime.PROFILE), ('tool_id', runtime.OPENSSL),
    ('executable', '/usr/bin/whatweb'), ('interpreter', '/usr/bin/env'), ('version', '2')])
def test_distinct_runtime_envelope_cannot_be_relabelled(field, value):
    candidate = manifest()
    candidate[field] = value
    with pytest.raises(ValueError):
        runtime.validate_manifest(candidate, tool_id=runtime.WHATWEB)


@pytest.mark.parametrize('fault', ['missing', 'duplicate', 'reordered', 'boolean_index', 'negative_index',
    'unknown_index', 'boolean_size', 'zero_size', 'large_size', 'invalid_digest', 'unknown_field', 'expanded_rows'])
def test_strict_manifest_refuses_incomplete_noncanonical_or_unbounded_closures(fault):
    value = manifest()
    if fault == 'missing': value['files'].pop()
    elif fault == 'duplicate': value['files'][-1] = value['files'][0]
    elif fault == 'reordered': value['files'].reverse()
    elif fault == 'boolean_index': value['files'][0][0] = True
    elif fault == 'negative_index': value['files'][0][0] = -1
    elif fault == 'unknown_index': value['files'][0][0] = len(whatweb.fixed_entries())
    elif fault == 'boolean_size': value['files'][0][1] = True
    elif fault == 'zero_size': value['files'][0][1] = 0
    elif fault == 'large_size': value['files'][0][1] = whatweb.MAX_FILE_BYTES + 1
    elif fault == 'invalid_digest': value['files'][0][2] = 'Z' * 64
    elif fault == 'unknown_field': value['roots'] = ['/tmp']
    else: value['files'] = runtime.runtime_files(value)
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize('path', ['/usr/bin/sh', '/usr/bin/env', '/usr/bin/python3', '/root/.gem/credentials',
    '/usr/share/whatweb/plugins/wordpress.rb', '/usr/share/whatweb/plugins/bootstrap.rb',
    '/usr/lib/ruby/vendor_ruby/rchardet.rb', '/usr/lib/x86_64-linux-gnu/extra.so',
    '/tool/../secret', '/tmp/custom.rb'])
def test_no_extra_executable_plugin_gem_library_or_private_file_is_admissible(path):
    value = manifest()
    row = {'source': path, 'destination': path, 'size': 4, 'sha256': hashlib.sha256(b'data').hexdigest()}
    files = runtime.runtime_files(value)
    files[-1] = row  # Keep the permitted count; the closure must still be exact.
    changed = whatweb.compact_manifest({**value, 'files': sorted(files, key=lambda item: item['destination'])})
    with pytest.raises(ValueError):
        runtime.validate_manifest(changed)


@pytest.mark.parametrize('component', ['compiled:whatweb-guard', 'compiled:whatweb-json-marker'])
@pytest.mark.parametrize('fault', ['hash', 'size', 'source'])
def test_fresh_manifest_hash_cannot_replace_compiled_guard_or_build_marker(component, fault):
    value = manifest()
    files = runtime.runtime_files(value)
    row = next(item for item in files if item['source'] == component)
    if fault == 'hash': row['sha256'] = 'a' * 64
    elif fault == 'size': row['size'] += 1
    else: row['source'] = '/tmp/substitute.rb'
    changed = whatweb.compact_manifest({**value, 'files': files})
    with pytest.raises(ValueError):
        runtime.manifest_digest(changed)


def test_fixed_cli_uses_only_five_explicit_passive_plugin_files_and_one_http_origin():
    argv = runtime.FIXED_ARGV[runtime.WHATWEB]
    assert runtime.EXECUTABLES[runtime.WHATWEB] == '/usr/bin/ruby3.3'
    assert argv[:5] == ('/tool/ruby', '--disable=did_you_mean,error_highlight,syntax_suggest',
                       '-r', '/tool/data/whatweb-guard.rb', '/tool/whatweb')
    assert argv[-1] == 'http://127.0.0.1:8080/harbordesk/portal.html'
    assert [arg for arg in argv if arg.startswith('--plugins=')] == [
        '--plugins=' + ','.join('/usr/share/whatweb/plugins/' + name for name in (
            'title.rb', 'http-server.rb', 'x-powered-by-header.rb', 'meta-generator.rb', 'jquery.rb'))]
    assert {'--aggression=1', '--follow-redirect=never', '--max-redirects=0', '--max-threads=1',
            '--open-timeout=1', '--read-timeout=1', '--no-cookies', '--quiet', '--log-json=-',
            '--header=Connection:close', '--header=Accept-Encoding:identity'} <= set(argv)
    assert not any(arg.startswith(('--user=', '--proxy', '--cookie=', '--input-file=', '--custom-plugin=',
                                   '--log-json-verbose=', '--url-prefix=', '--url-suffix=')) for arg in argv)


def test_environment_and_landlock_do_not_expose_host_plugins_gems_or_secrets(monkeypatch):
    for name in ('HOME', 'GEM_HOME', 'GEM_PATH', 'RUBYOPT', 'RUBYLIB', 'http_proxy', 'HTTP_PROXY', 'LD_PRELOAD'):
        monkeypatch.setenv(name, '/private/injected')
    environment = runtime.execution_environment(runtime.WHATWEB)
    assert not {'HOME', 'RUBYOPT', 'RUBYLIB', 'http_proxy', 'HTTP_PROXY', 'LD_PRELOAD'} & environment.keys()
    assert environment['GEM_HOME'] == '/tool/no-user-gems'
    assert '/private' not in repr(environment)
    files = runtime.runtime_files(manifest())
    permissions = worker._landlock_permissions(manifest())
    assert {path for path, permission in permissions.items() if permission & 1} == {
        '/tool/ruby', '/lib64/ld-linux-x86-64.so.2'}
    assert {path for path, permission in permissions.items() if permission & 8} == {
        str(Path(row['destination']).parent) for row in files}
    assert all(permissions[row['destination']] & 4 for row in files)
    assert '/usr/bin/python3' not in permissions and '/home' not in permissions
    assert not any(path.startswith('/etc/') for path in permissions)


def test_ruby_threads_use_existing_kernel_filter_and_sixteen_task_cap(monkeypatch):
    seen, limits = [], {}
    monkeypatch.setattr(worker.common, 'syscall_filter', lambda **kwargs: seen.append(kwargs))
    worker.syscall_filter(runtime.WHATWEB)
    assert seen == [{'allow_threads': True}]
    monkeypatch.setattr(worker.resource, 'getrlimit', lambda _: (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    monkeypatch.setattr(worker.resource, 'setrlimit', lambda key, value: limits.update({key: value}))
    worker._limits(runtime.WHATWEB)
    assert limits[resource.RLIMIT_NPROC] == (16, 16)
    assert limits[resource.RLIMIT_AS] == (256 * 1024 * 1024,) * 2
    assert limits[resource.RLIMIT_CPU] == (5, 5)
    assert limits[resource.RLIMIT_FSIZE] == (0, 0)


def test_snapshot_expands_every_file_and_supplies_only_compiled_guard_and_marker(monkeypatch):
    seen = []
    monkeypatch.setattr(runtime, 'sealed_snapshots', lambda *args, **kwargs: seen.append((args, kwargs)) or [])
    value, control = manifest(), object()
    assert runtime._snapshot(value, control) == []
    source, _, raw = whatweb.COMPILED[0]
    assert seen == [(({**value, 'files': runtime.runtime_files(value)}, source, raw, control),
        {'additional_compiled': tuple((source, raw) for source, _, raw in whatweb.COMPILED[1:])})]


def test_runtime_inspection_reads_only_fixed_files_and_ldd_never_runs_whatweb(monkeypatch):
    seen = []
    monkeypatch.setattr(whatweb.Path, 'resolve', lambda path, **kwargs: Path(dict(
        (destination, source) for source, destination in whatweb.NATIVE_FILES).get(str(path), str(path))))
    monkeypatch.setattr(whatweb, '_read_regular', lambda path: b'\x7fELFdata')
    monkeypatch.setattr(whatweb, '_trusted_program', lambda name: '/usr/bin/' + name)
    listing = '\n'.join(destination + ' (0x100)' for _, destination in whatweb.NATIVE_FILES).encode()
    monkeypatch.setattr(whatweb, '_runtime_probe', lambda argv, *args: seen.append(argv) or listing)
    value = runtime.inspect_tool_runtime(runtime.WHATWEB, SimpleNamespace(check=lambda: None))
    assert runtime.validate_manifest(value) == value
    assert len(seen) == 1 and seen[0][0] == '/usr/bin/ldd'
    assert seen[0][1] == '/usr/bin/ruby3.3' and '/usr/bin/whatweb' not in seen[0]
    monkeypatch.setattr(whatweb, '_runtime_probe', lambda *args: listing + b'\n/usr/lib/x86_64-linux-gnu/extra.so (0x101)')
    with pytest.raises(IsolationUnavailable, match='finite closure'):
        runtime.inspect_tool_runtime(runtime.WHATWEB, SimpleNamespace(check=lambda: None))


def test_outer_descriptor_increase_is_selected_by_a_case_bound_whatweb_tag():
    from recon_cockpit.secure_agent import launcher_protocol
    from recon_cockpit.secure_agent.network_tools_lab_contract import identity
    from test_secure_network_tools_runtime import configuration, manifest as shared_manifest
    from uuid import uuid4
    closure = {'network_tools_runtime': manifest()}
    config = configuration('whatweb-ok')
    tag = 'whatweb-tools-launch-preconditions'
    assert launcher_protocol.runtime_tag(config, closure) == tag
    launcher_protocol.validate_runtime_tag(tag, config, closure)
    for other in ('network-tools-launch-preconditions', 'smb-tools-launch-preconditions',
                  'kerberos-tools-launch-preconditions', 'fixture'):
        with pytest.raises(ValueError):
            launcher_protocol.validate_runtime_tag(other, config, closure)
    for tool in (runtime.DIG, runtime.SMB, runtime.KERBRUTE, runtime.OPENSSL):
        with pytest.raises(ValueError):
            launcher_protocol.validate_runtime_tag(tag, config, {'network_tools_runtime': shared_manifest(tool)})
    # A fresh matching outer tag cannot substitute the closure into another
    # case; the independently checked action still binds the selected tool.
    old_config = {**configuration('openssl-ok'), 'owned_lab': identity('openssl-ok', str(uuid4()))}
    complete_closure = {'stdlib': '/usr/lib/python3.13',
        'files': ['/usr/bin/python3', '/usr/sbin/nft', '/usr/bin/bwrap', '/usr/bin/nsenter'], **closure}
    with pytest.raises(ValueError, match='launcher_network_tool_runtime_changed'):
        launcher_protocol.initial({'configuration': old_config, 'runtime': complete_closure, 'deadline': 130}, 100)


def test_whatweb_outer_staging_limits_leave_native_and_other_tool_limits_unchanged(monkeypatch):
    from test_secure_kerberos_runtime import test_launcher_go_reservation_is_scoped_and_preserves_other_caps
    test_launcher_go_reservation_is_scoped_and_preserves_other_caps(
        monkeypatch, {'whatweb_runtime': True}, 256, 16, 256)
    # Exact native limits remain narrower after sealing and descriptor cleanup.
    test_ruby_threads_use_existing_kernel_filter_and_sixteen_task_cap(monkeypatch)
