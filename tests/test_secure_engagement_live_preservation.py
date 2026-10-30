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
    checked = 0
    amended = set()
    for row in baseline:
        path = ROOT / row['path']
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode)
        assert ('100755' if info.st_mode & 0o111 else '100644') == row['mode']
        if row['path'] not in status:
            raw = path.read_bytes()
            if row['path'] in changes:
                raw = _restore_approved_source_change(raw, row['mode'], changes[row['path']])
                amended.add(row['path'])
            else:
                checked += 1
            assert hashlib.sha256(raw).hexdigest() == row['sha256'], row['path']
            assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['git_blob']
    assert checked == 1090 and amended == set(_APPROVED_SOURCE_CHANGES)
    tracked = set(subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().rstrip('\0').split('\0'))
    assert tracked <= {row['path'] for row in baseline} | _new_paths()
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
