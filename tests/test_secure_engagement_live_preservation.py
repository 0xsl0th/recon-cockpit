"""Pin accepted implementations and the complete S4.2c validation inventory."""

import ast
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
GATES = json.loads((ROOT / 'docs/stage4-engagement-live-gates.json').read_text())

_ACCEPTED_MANIFEST_SHA256 = '3a2ae8d0150fbf6f44ca2630508fc7f4199844df9805ffba39a39b62df637e54'
_MAIN_SYNC_PATH = 'docs/stage4-engagement-live-main-sync-20261116.json'
_MAIN_SYNC_SHA256 = '7d9c537c03b4624c8a77ee50ec1e0922a128fe973deaccc56632257c880bc446'
_APPROVED_SOURCE_CHANGES = {'pyproject.toml': {'after_bytes': 745,
                    'after_git_blob': '3f2135c18703c6d8b8ffdb5dcce600c612839a2f',
                    'after_sha256': '3989fe11357acb3144ea7c5e0dc87aebe970e325f32e1a9fbbb1f82954574832',
                    'after_text': 'test = ["pytest==9.1.1"]\n',
                    'before_bytes': 741,
                    'before_git_blob': '1605ee799fa1690b2d0296d007bb41c3056970b3',
                    'before_sha256': '3af7f08a9be31b066518afbffcc72512ab6f10aa7ff18bc4489b19a08498c8d1',
                    'before_text': 'test = ["pytest>=8"]\n',
                    'id': 'S42C-A11',
                    'mode': '100644',
                    'path': 'pyproject.toml'},
 'tests/test_secure_engagement_dispatch_preservation.py': {'after_bytes': 12140,
                                                           'after_git_blob': 'da635c0265257b996363677cbd6347122e362dc3',
                                                           'after_sha256': '1b1c50e2d1d3738c5199951eba0ebb303d9de305dcbb3ea22035c0a39f01c16a',
                                                           'after_text': '        raw = '
                                                                         'path.read_bytes()\n'
                                                                         '        '
                                                                         'exact_dependency_changes = '
                                                                         "{'pyproject.toml': "
                                                                         "('3989fe11357acb3144ea7c5e0dc87aebe970e325f32e1a9fbbb1f82954574832',\n"
                                                                         '                            '
                                                                         "b'test = "
                                                                         '["pytest>=8"]\\n\',\n'
                                                                         '                            '
                                                                         "b'test = "
                                                                         '["pytest==9.1.1"]\\n\'),\n'
                                                                         "         'uv.lock': "
                                                                         "('51eb36224d55e0b365af284f76933350082f184f23a12d53b4c4dff3e3a62eb8',\n"
                                                                         "                     b'    { "
                                                                         'name = "pytest", marker = '
                                                                         '"extra == \\\'test\\\'", '
                                                                         'specifier = ">=8" },\\n\',\n'
                                                                         "                     b'    { "
                                                                         'name = "pytest", marker = '
                                                                         '"extra == \\\'test\\\'", '
                                                                         'specifier = "==9.1.1" '
                                                                         "},\\n')}\n"
                                                                         '        if name in '
                                                                         'exact_dependency_changes:\n'
                                                                         '            after_sha256, '
                                                                         'before, after = '
                                                                         'exact_dependency_changes[name]\n'
                                                                         '            assert '
                                                                         'hashlib.sha256(raw).hexdigest() '
                                                                         '== after_sha256\n'
                                                                         '            assert '
                                                                         'raw.count(after) == 1 and '
                                                                         'before not in raw\n'
                                                                         '            restored = '
                                                                         'raw.replace(after, before)\n'
                                                                         '            assert '
                                                                         'restored.count(before) == 1 '
                                                                         'and after not in restored\n'
                                                                         '            assert '
                                                                         'restored.replace(before, '
                                                                         'after) == raw\n'
                                                                         '            raw = restored\n'
                                                                         '        assert '
                                                                         'hashlib.sha256(raw).hexdigest() '
                                                                         '== expected["sha256"], name\n',
                                                           'before_bytes': 11132,
                                                           'before_git_blob': '3fdfa78356f85981a85b7f2c66aaa1f4967ca04c',
                                                           'before_sha256': 'f4bb2fbabceddc15e6d1ab33c9c8c8e3edf36cd26e14f21f9b2d3e9da053b003',
                                                           'before_text': '        assert '
                                                                          'hashlib.sha256(path.read_bytes()).hexdigest() '
                                                                          '== expected["sha256"], '
                                                                          'name\n',
                                                           'id': 'S42C-A11-preservation-check',
                                                           'mode': '100644',
                                                           'path': 'tests/test_secure_engagement_dispatch_preservation.py'},
 'uv.lock': {'after_bytes': 6991,
             'after_git_blob': 'a22aa0896ef455ecef53c55977763d742ca122e2',
             'after_sha256': '51eb36224d55e0b365af284f76933350082f184f23a12d53b4c4dff3e3a62eb8',
             'after_text': '    { name = "pytest", marker = "extra == \'test\'", specifier = "==9.1.1" '
                           '},\n',
             'before_bytes': 6987,
             'before_git_blob': 'd142ce204b9fef4cf8c7a10012e1563f5726bbba',
             'before_sha256': '10b4fdf0e79e5878ef92641f9537ea5068331de1d1599caa6ab3ab0267ba2b26',
             'before_text': '    { name = "pytest", marker = "extra == \'test\'", specifier = ">=8" '
                            '},\n',
             'id': 'S42C-A11-lock-metadata',
             'mode': '100644',
             'path': 'uv.lock'}}

def _restore_approved_source_change(raw, mode, change):
    # Exact literal transformations retain both original accepted-source pins.
    assert change == _APPROVED_SOURCE_CHANGES[change['path']]
    assert mode == change['mode']
    assert len(raw) == change['after_bytes']
    assert hashlib.sha256(raw).hexdigest() == change['after_sha256']
    assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == change['after_git_blob']
    before, after = change['before_text'].encode(), change['after_text'].encode()
    assert raw.count(after) == 1 and before not in raw
    restored = raw.replace(after, before)
    assert restored.count(before) == 1 and after not in restored
    assert restored.replace(before, after) == raw
    assert len(restored) == change['before_bytes']
    assert hashlib.sha256(restored).hexdigest() == change['before_sha256']
    assert hashlib.sha1(b'blob ' + str(len(restored)).encode() + b'\0' + restored).hexdigest() == change['before_git_blob']
    return restored



def _new_paths():
    allowed = GATES['change_allowlist']
    return set(allowed['proposed_new_production'] + allowed['confirmed_new_tests_and_helpers']
               + allowed['new_contracts'])


def _main_sync():
    path = ROOT / _MAIN_SYNC_PATH
    mode = path.lstat().st_mode
    assert stat.S_ISREG(mode) and not mode & 0o111
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == _MAIN_SYNC_SHA256
    amendment = json.loads(raw)
    assert amendment['accepted_manifest_sha256'] == _ACCEPTED_MANIFEST_SHA256
    return amendment


def _check_sync_bytes(raw, expected):
    assert len(raw) == expected['bytes']
    assert hashlib.sha256(raw).hexdigest() == expected['sha256']
    assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected['git_blob']


def _restore_main_sync_dispatch(raw, mode, change):
    # Undo only the upstream documentation guard before applying original A11.
    assert mode == change['mode']
    _check_sync_bytes(raw, change['after'])
    before, after = change['before_text'].encode(), change['after_text'].encode()
    assert raw.count(after) == 1 and before not in raw
    restored = raw.replace(after, before)
    assert restored.count(before) == 1 and after not in restored
    assert restored.replace(before, after) == raw
    _check_sync_bytes(restored, change['before'])
    return restored


def _restore_fixture_change(raw, mode, change):
    # Reverse the separately pinned fixture/guard edits before historical checks.
    assert mode == change['mode']
    _check_sync_bytes(raw, change['after'])
    restored = raw
    for edit in reversed(change['replacements']):
        before, after = edit['before_text'].encode(), edit['after_text'].encode()
        assert restored.count(after) == 1
        original = restored.replace(after, before)
        assert original.count(before) == 1 and after not in original
        assert original.replace(before, after) == restored
        restored = original
    _check_sync_bytes(restored, change['before'])
    return restored


def test_exact_accepted_source_and_change_allowlist():
    baseline = GATES['source_baseline']['complete_tracked_manifest']
    allowed = GATES['change_allowlist']
    assert len(baseline) == 1101 and len(_new_paths()) == 39
    status = set(allowed['existing_status_only'])
    assert len(status) == 8 and 'pyproject.toml' not in status
    assert allowed['other_existing_changes'] is False
    changes = {row['path']: row for row in (allowed['approved_test_dependency_change'],
                                           allowed['approved_lock_metadata_change'],
                                           allowed['approved_preservation_test_change'])}
    assert changes == _APPROVED_SOURCE_CHANGES
    assert not status & changes.keys()
    assert GATES['source_baseline']['complete_tracked_manifest_sha256'] == _ACCEPTED_MANIFEST_SHA256
    encoded = json.dumps(baseline, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    assert hashlib.sha256(encoded).hexdigest() == _ACCEPTED_MANIFEST_SHA256
    assert GATES['source_baseline']['accepted_nonstatus_unchanged_required'] == 1090
    assert GATES['source_baseline']['accepted_nonstatus_approved_test_dependency_changes_required'] == 1
    assert GATES['source_baseline']['accepted_nonstatus_approved_preservation_test_changes_required'] == 1
    assert GATES['source_baseline']['accepted_nonstatus_approved_lock_metadata_changes_required'] == 1
    # Keep the historical manifest/A11 records intact; main synchronization is
    # separately pinned and never supplies acceptance credit for the new tree.
    sync = _main_sync()
    refreshed = {row['path']: row for row in sync['refreshed_documents']}
    assert len(refreshed) == 4 and not refreshed.keys() & (status | changes.keys())
    dispatch_change = sync['dispatch_preservation_change']
    assert dispatch_change['path'] == 'tests/test_secure_engagement_dispatch_preservation.py'
    fixture_change = sync['approval_failure_fixture_change']
    assert fixture_change['path'] == 'tests/test_name_tls_approval_failure.py'
    assert fixture_change['path'] not in status | changes.keys() | refreshed.keys()
    fixture_guard = sync['approval_failure_dispatch_guard_change']
    assert fixture_guard['path'] == dispatch_change['path']
    assert fixture_guard['before'] == dispatch_change['after']
    checked = 0
    amended = set()
    refreshed_checked = set()
    fixture_checked = set()
    for row in baseline:
        path = ROOT / row['path']
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode)
        assert ('100755' if info.st_mode & 0o111 else '100644') == row['mode']
        if row['path'] not in status:
            raw = path.read_bytes()
            if row['path'] in refreshed:
                change = refreshed[row['path']]
                assert change['mode'] == row['mode']
                assert change['before']['sha256'] == row['sha256']
                assert change['before']['git_blob'] == row['git_blob']
                _check_sync_bytes(raw, change['after'])
                refreshed_checked.add(row['path'])
                continue
            if row['path'] == fixture_change['path']:
                assert fixture_change['before']['sha256'] == row['sha256']
                assert fixture_change['before']['git_blob'] == row['git_blob']
                raw = _restore_fixture_change(raw, row['mode'], fixture_change)
                fixture_checked.add(row['path'])
            if row['path'] == dispatch_change['path']:
                raw = _restore_fixture_change(raw, row['mode'], fixture_guard)
                raw = _restore_main_sync_dispatch(raw, row['mode'], dispatch_change)
            if row['path'] in changes:
                raw = _restore_approved_source_change(raw, row['mode'], changes[row['path']])
                amended.add(row['path'])
            elif row['path'] not in fixture_checked:
                checked += 1
            assert hashlib.sha256(raw).hexdigest() == row['sha256'], row['path']
            assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['git_blob']
    assert checked == 1085 and amended == set(_APPROVED_SOURCE_CHANGES)
    assert refreshed_checked == refreshed.keys()
    assert fixture_checked == {fixture_change['path']}
    assert checked + len(refreshed_checked) + len(fixture_checked) == 1090
    assert sync['source_accounting']['unchanged_nonstatus_files'] == checked
    assert sync['source_accounting']['approved_portable_fixture_changes'] == len(fixture_checked)
    backup = sync['upstream_readme_backup']
    original = next(row for row in baseline if row['path'] == backup['original_baseline_path'])
    path = ROOT / backup['path']
    mode = path.lstat().st_mode
    assert stat.S_ISREG(mode)
    assert ('100755' if mode & 0o111 else '100644') == backup['mode'] == original['mode']
    _check_sync_bytes(path.read_bytes(), backup)
    assert backup['sha256'] == original['sha256'] and backup['git_blob'] == original['git_blob']
    sync_additions = {_MAIN_SYNC_PATH, backup['path']}
    assert len(sync_additions) == 2 and not sync_additions & _new_paths()
    # Admit only the reviewed S4.3 design documents; historical checks stay intact.
    s43_documents = {
        'docs/stage4-synthetic-custody.md': 'cc10cb881406aa60f1537b4456cd2056f24202e3b10c0fe380d606d1394cddbf',
        'docs/stage4-synthetic-custody-gates.json': 'ea95c23940004108f9b69b2a3544b267edcf9e4b5972dd3c477f1d2579a23451',
    }
    for name, expected_sha256 in s43_documents.items():
        path = ROOT / name
        mode = path.lstat().st_mode
        assert stat.S_ISREG(mode) and not mode & 0o111
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected_sha256, name
    # Independently reviewed intrinsic codec slice: exact paths, never a package wildcard.
    s43_codec_files = {
        'recon_cockpit_synthetic/__init__.py': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'recon_cockpit_synthetic/contract.py': 'c2864df6eb91c56d85851af35eb9ddca036144cff1fd5063265250d2d1e3823a',
        'recon_cockpit_synthetic/codec.py': '56ec2e69c512c5229421e60166a888be15f1374f6f93e19ee95ed23411688d4f',
        'tests/test_secure_synthetic_custody_contract.py': '0d47af6179d927b49e692eade2b3aed4f2b06abb966b1cca8f1659dd45976428',
    }
    s43_codec_imports = {
        'recon_cockpit_synthetic/__init__.py': set(),
        'recon_cockpit_synthetic/contract.py': set(),
        'recon_cockpit_synthetic/codec.py': {'datetime', 'json', 're', 'recon_cockpit_synthetic.contract'},
        'tests/test_secure_synthetic_custody_contract.py': {'json', 'pytest', 'recon_cockpit_synthetic.codec'},
    }
    forbidden = {'__import__', 'eval', 'exec', 'compile', 'globals', 'locals',
                 'vars', 'getattr', 'setattr', 'delattr', 'open', 'input'}
    for name, expected_sha256 in s43_codec_files.items():
        path = ROOT / name
        mode = path.lstat().st_mode
        assert stat.S_ISREG(mode) and not mode & 0o111
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected_sha256, name
        tree = ast.parse(raw)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert node.level == 0 and all(alias.name != '*' for alias in node.names)
                imports.add(node.module)
            elif isinstance(node, ast.Name):
                assert node.id not in forbidden, (name, node.id)
            elif isinstance(node, ast.Attribute):
                assert node.attr not in forbidden, (name, node.attr)
        assert imports == s43_codec_imports[name], name
        for node in tree.body:
            if isinstance(node, ast.Assign):
                ast.literal_eval(node.value)  # No executable module-level initializers.
            elif isinstance(node, ast.Expr):
                assert isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
            else:
                assert isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef))
        if name == 'recon_cockpit_synthetic/__init__.py':
            assert raw == b''
    tracked = set(subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().rstrip('\0').split('\0'))
    assert tracked <= {row['path'] for row in baseline} | _new_paths() | sync_additions | s43_documents.keys() | s43_codec_files.keys()
    assert all((ROOT / name).is_file() for name in _new_paths())


def test_historical_contracts_and_profile_recipes_remain_pinned():
    historical = {row['path']: row for row in GATES['source_baseline']['complete_tracked_manifest']
                  if row['path'].startswith(('docs/stage4-', 'recon_cockpit/secure_agent/engagement_',
                                             'recon_cockpit/secure_agent/configurable_'))}
    assert historical
    assert 'recon_cockpit/secure_agent/engagement_dispatch_contract.py' in historical
    assert 'recon_cockpit/secure_agent/configurable_contract.py' in historical
    for name, row in historical.items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest() == row['sha256']
    from recon_cockpit.secure_agent import engagement_live_contract as live
    from test_secure_engagement_live_contract import opened, prepared
    from recon_cockpit.secure_agent import configurable_contract
    selected = opened()
    for slot, step in [('http_identify', 1), ('http_headers', 2)]:
        actual = prepared(slot, opened_value=selected)
        expected = configurable_contract.action(selected['scope'], step)
        assert actual['action'] == expected
        assert live.validate_prepared(actual) == actual


def test_exact_case_inventory_and_parent_mapping():
    cases = GATES['cases']
    assert len(cases) == len({r['id'] for r in cases}) == len({r['nodeid'] for r in cases}) == 288
    nodes = {r['nodeid'] for r in cases}
    files = sorted({node.split('::')[0] for node in nodes})
    result = subprocess.run([sys.executable, '-m', 'pytest', '-o', 'addopts=', '--collect-only', '-q', *files],
                            cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    collected = {line.strip() for line in result.stdout.splitlines() if line.startswith('tests/') and '::' in line}
    assert nodes <= collected
    new = {node for node in collected if node.split('::')[0] in GATES['change_allowlist']['confirmed_new_tests_and_helpers']}
    assert new == {r['nodeid'] for r in cases if r['group'] != 'accepted_integration_regression'}
    mappings = GATES['parent_mapping']
    assert len(mappings) == 26 and sum(r['physical_gate_required'] for r in mappings) == 18
    for parent in mappings:
        for case_id in parent['case_ids']:
            child = next(r for r in cases if r['id'] == case_id)
            assert parent['parent_id'] in child['parent_cases']
    for child in cases:
        for parent_id in child['parent_cases']:
            parent = next(r for r in mappings if r['parent_id'] == parent_id)
            assert child['id'] in parent['case_ids']


def test_inspection_and_runtime_imports_preserve_role_separation():
    from recon_cockpit.secure_agent import engagement_live_runtime as runtime
    assert runtime.SPEC['source_partitions'] == GATES['runtime_contract']['source_partitions']
    for leaf in ('headers_extra', 'nmap_extra', 'parser_extra', 'endpoint_extra'):
        names = set(runtime.SPEC['source_partitions']['common'] + runtime.SPEC['source_partitions'][leaf])
        assert not names & {'engagement_dispatch_store', 'engagement_live_broker_worker',
                            'engagement_live_approval_worker', 'engagement_live_audit'}
    # Inspectors may launch only the fixed parser. Imports of authority owners
    # cannot be hidden in helper functions or conditional import blocks.
    for name in ('recon_cockpit/secure_agent/engagement_live_evidence.py', 'scripts/engagement_live_inspect.py'):
        tree = ast.parse((ROOT/name).read_text())
        modules = {node.module.rsplit('.',1)[-1] for node in ast.walk(tree)
                   if isinstance(node, ast.ImportFrom) and node.module}
        assert not modules & {'engagement_dispatch_store', 'engagement_live_session',
            'engagement_live_broker', 'engagement_live_client', 'engagement_live_endpoint',
            'engagement_live_approval', 'engagement_live_launcher', 'sqlite3'}
