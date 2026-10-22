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


def _new_paths():
    allowed = GATES['change_allowlist']
    return set(allowed['proposed_new_production'] + allowed['confirmed_new_tests_and_helpers']
               + allowed['new_contracts'])


def test_exact_accepted_source_and_change_allowlist():
    baseline = GATES['source_baseline']['complete_tracked_manifest']
    allowed = GATES['change_allowlist']
    assert len(baseline) == 1101 and len(_new_paths()) == 39
    status = set(allowed['existing_status_only'])
    checked = 0
    for row in baseline:
        path = ROOT / row['path']
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode)
        assert ('100755' if info.st_mode & 0o111 else '100644') == row['mode']
        if row['path'] not in status:
            raw = path.read_bytes()
            assert hashlib.sha256(raw).hexdigest() == row['sha256'], row['path']
            assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['git_blob']
            checked += 1
    assert checked == 1093
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
