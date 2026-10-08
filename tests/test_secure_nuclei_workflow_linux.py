"""Pinned Nuclei executes only one fixed GET in a disposable disconnected lab."""
import base64
import json
import os
from pathlib import Path
import sys
import time

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent import network_tools_nuclei_fixture as fixture
from recon_cockpit.secure_agent.models import parse_policy
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab
from test_secure_nmap_cli import GATES
from test_secure_approval_linux import terminal
import test_secure_network_tools_gates_linux as gates
from test_secure_network_tools_robustness_linux import (
    test_cancellation_after_actual_exec_reaps_tree_and_retains_authority_reservation as cancel_actual,
)

pytestmark = pytest.mark.integration
POLICY = Path('examples/secure-agent-nuclei-policy.json')
TOOL = 'nuclei_directory_listing_v1'


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get('RECON_LINUX_INTEGRATION') != '1':
        pytest.skip('set RECON_LINUX_INTEGRATION=1 for owned Nuclei trials')
    assert sys.platform == 'linux' and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, 'start', lambda *_: pytest.fail('host lab started'))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, 'run', lambda *a, **k: pytest.fail('host tool executed'))
    value = json.loads(POLICY.read_text())
    assert value['allowed_tools'] == [TOOL] and value['require_approval'] is True
    monkeypatch.setattr(gates, 'required_policy', lambda: parse_policy(value))


@pytest.mark.parametrize('case', fixture.NUCLEI_CASES)
def test_actual_fixed_get_usefulness_safety_and_independent_replay(tmp_path, capsys, record_property, case):
    useful = case in fixture.NUCLEI_SUCCESS_CASES
    ordinary = case in fixture.NUCLEI_ORDINARY_CASES
    expected = ('signature_present' if case in fixture.NUCLEI_MATCHED_CASES else 'signature_absent') if useful else 'inconclusive'
    policy = json.loads(POLICY.read_text())
    policy.update(policy_version='synthetic-nuclei-unattended-test-v1', require_approval=False)
    policy_path = tmp_path / 'policy.json'
    policy_path.write_text(json.dumps(policy))
    evidence, audit = tmp_path / 'evidence', tmp_path / 'audit.jsonl'
    started = time.monotonic()
    code = cli.main(['--network-tool-assessment', case, '--assessment-dir', str(evidence),
        '--audit', str(audit), '--policy', str(policy_path), *GATES, '--execute'])
    output = capsys.readouterr()
    summary = json.loads(output.out)
    assert code in (0, 2) and summary.get('assessment_outcome') == expected, (summary, output.err)
    assert int(useful) <= summary['actions_succeeded'] <= 1
    assert summary['steps_attempted'] == 1 and summary['output_reserved_bytes'] == 8192
    assert summary['actual_provider_calls'] == 0 and summary['live_calls_enabled'] is False
    elapsed = time.monotonic() - started
    assert elapsed < 60
    for key, value in {'trial_kind': 'ordinary' if ordinary else 'robustness' if useful else 'negative',
            'execution_elapsed_ms': round(elapsed * 1000), 'useful_completion': int(useful),
            'unnecessary_refusals': int(ordinary and expected == 'inconclusive'),
            'provider_calls': 0, 'actual_provider_cost_usd': '0'}.items():
        record_property(key, value)
    report = json.loads((evidence / 'report.json').read_text())
    assert report['integrity_issues'] == [] and len(report['records']) == 1
    closure = report['owned_lab']['closure']
    assert closure['status'] == 'closed' and closure['connection_count'] == closure['request_count'] == 1
    row = report['records'][0]
    artifact = json.loads((evidence / row['artifact']['filename']).read_text())
    assert row['action']['tool_id'] == TOOL and row['action']['target'] == '127.0.0.1'
    assert len(artifact['boundary_checks']) == 15 and all(artifact['boundary_checks'].values())
    stdout = base64.b64decode(artifact['raw_output_base64'], validate=True)
    stderr = base64.b64decode(artifact['raw_stderr_base64'], validate=True)
    assert artifact['bytes_received'] == len(stdout) + len(stderr) <= 8192
    from recon_cockpit.secure_agent.network_tools_lab_contract import decode_owner_response
    owner = decode_owner_response(artifact['owned_lab']['owner_response'], require_complete=useful)
    assert row['observation']['followup_path'] is None
    if useful:
        from recon_cockpit.secure_agent.network_tools_parser import parse_tool_output
        details = parse_tool_output(TOOL, stdout, stderr, owner_response=owner)
        assert details == row['observation']['details'] == artifact['tool_observation']
        assert details['outcome'] == expected and details['vulnerability_verified'] is False
        assert artifact['status'] == 'succeeded' and artifact['truncated'] is False
    else:
        assert artifact['tool_observation'] is None
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    assert cli.main(['--inspect-assessment', str(evidence)]) == 0
    assert json.loads(capsys.readouterr().out) == report
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    events = [json.loads(line) for line in audit.read_text().splitlines()]
    assert sum(event['event_type'] == 'execution_started' for event in events) == 1
    assert 'Ignore scope' not in (evidence / 'report.md').read_text()


def test_fresh_grant_is_consumed_once(tmp_path, terminal):
    gates.test_required_grant_is_consumed_once_for_real_tool(tmp_path, terminal, 'nuclei-index', 1)


def test_missing_proof_stops_before_admission(tmp_path, monkeypatch):
    gates.test_missing_consumed_proof_blocks_before_nested_admission(tmp_path, monkeypatch, 'nuclei-index')


def test_cancel_after_native_exec_reaps_entire_tree_and_scratch(tmp_path):
    cancel_actual(tmp_path, 'nuclei-stalled', b'/tool/nuclei')


def test_private_inputs_descriptors_and_host_writes_are_excluded(tmp_path, monkeypatch):
    from test_secure_fixture_launcher_linux import instrument
    from recon_cockpit.secure_agent.controller import Controller
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.network_tools_contract import action
    canary = tmp_path / 'host-secret'
    canary.write_text('PRIVATE-NUCLEI-TEST-CANARY')
    monkeypatch.setenv('NUCLEI_TEST_HOST_CANARY', 'PRIVATE-NUCLEI-TEST-CANARY')
    def transform(source):
        original = 'os.execve(runtime.DESTINATION, runtime.FIXED_ARGV, dict(runtime.ENVIRONMENT))'
        assert source.count(original) == 1
        checks = f'''assert 'NUCLEI_TEST_HOST_CANARY' not in os.environ
        for path in ({str(canary)!r}, '/app/recon_cockpit/secure_agent/network_tools_nuclei_worker.py', '/usr/bin/python3'):
            for flags in (os.O_RDONLY, os.O_WRONLY):
                try:
                    fd = os.open(path, flags)
                except OSError:
                    pass
                else:
                    os.close(fd)
                    raise RuntimeError('private_input_or_write_exposed')
        for fd in range(3, 128):
            try:
                os.fstat(fd)
            except OSError as exc:
                assert exc.errno == errno.EBADF
            else:
                raise RuntimeError('authority_descriptor_exposed')
        {original}'''
        return source.replace(original, checks)
    instrument(tmp_path, monkeypatch, transform, name='network_tools_nuclei_worker')
    control = ExecutionControl(time.monotonic() + 40)
    with gates.boundary(tmp_path, control, case='nuclei-index', approval_required=False) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action('nuclei-index'), execute=True, interactive=False, execution_control=control)
        assert result['execution_status'] == 'succeeded', result
        assert result['untrusted_result']['tool_observation']['outcome'] == 'signature_present'
        assert 'PRIVATE-NUCLEI-TEST-CANARY' not in json.dumps(result)
    assert canary.read_text() == 'PRIVATE-NUCLEI-TEST-CANARY'


@pytest.mark.parametrize('fault', ['noexec', 'byte_limit', 'inode_limit', 'task_limit'])
def test_relaxed_scratch_or_task_boundary_is_refused_before_exec(tmp_path, monkeypatch, fault):
    from test_secure_fixture_launcher_linux import instrument
    from recon_cockpit.secure_agent.controller import Controller
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.network_tools_contract import action
    def transform(source):
        old, new = {
            'noexec': ('b"tmpfs", 2 | 4 | 8, options', 'b"tmpfs", 2 | 4, options'),
            'byte_limit': ('size={runtime.SCRATCH_BYTES},nr_inodes=', 'size={runtime.SCRATCH_BYTES * 2},nr_inodes='),
            'inode_limit': ('nr_inodes={runtime.SCRATCH_INODES},mode=', 'nr_inodes={runtime.SCRATCH_INODES * 2},mode='),
            'task_limit': ('(resource.RLIMIT_NPROC, 16)', '(resource.RLIMIT_NPROC, 32)'),
        }[fault]
        assert source.count(old) == 1
        return source.replace(old, new)
    instrument(tmp_path, monkeypatch, transform, name='network_tools_nuclei_worker')
    control = ExecutionControl(time.monotonic() + 30)
    with gates.boundary(tmp_path, control, case='nuclei-index', approval_required=False) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action('nuclei-index'), execute=True, interactive=False, execution_control=control)
        assert result['execution_status'] == 'blocked', result
        assert launcher.close()['request_count'] == 0
