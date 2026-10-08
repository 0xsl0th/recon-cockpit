"""Execute the Git marker through the same owned authority and kernel gates as C16."""
import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_nuclei_git_fixture as fixture
from recon_cockpit.secure_agent import network_tools_nuclei_git_parser as parser
import test_secure_nuclei_workflow_linux as baseline

pytestmark = pytest.mark.integration
terminal = baseline.terminal


@pytest.fixture(autouse=True)
def git_profile(monkeypatch):
    monkeypatch.setattr(baseline, 'TOOL', 'nuclei_git_head_v1')
    monkeypatch.setattr(baseline, 'POLICY', Path('examples/secure-agent-nuclei-git-policy.json'))
    monkeypatch.setattr(baseline, 'fixture', SimpleNamespace(
        NUCLEI_CASES=fixture.NUCLEI_GIT_CASES,
        NUCLEI_SUCCESS_CASES=fixture.NUCLEI_GIT_SUCCESS_CASES,
        NUCLEI_ORDINARY_CASES=fixture.NUCLEI_GIT_ORDINARY_CASES,
        NUCLEI_MATCHED_CASES=fixture.NUCLEI_GIT_MATCHED_CASES))
    baseline.linux_only.__wrapped__(monkeypatch)


@pytest.mark.parametrize('case', fixture.NUCLEI_GIT_CASES)
def test_actual_fixed_get_usefulness_safety_and_independent_replay(tmp_path, capsys, record_property, case):
    baseline.test_actual_fixed_get_usefulness_safety_and_independent_replay(tmp_path, capsys, record_property, case)
    report = json.loads((tmp_path / 'evidence/report.json').read_text())
    assert report['records'][0]['action']['tool_id'] == 'nuclei_git_head_v1'
    assert all('directory-listing' not in limit for limit in report['limitations'])
    if case in fixture.NUCLEI_GIT_SUCCESS_CASES:
        row = report['records'][0]
        artifact = json.loads((tmp_path / 'evidence' / row['artifact']['filename']).read_text())
        native = json.loads(base64.b64decode(artifact['raw_output_base64']))
        assert native['path'] == '/.git/HEAD' and native['template-id'] == parser.TEMPLATE_ID
        assert row['observation']['details']['request'] == parser.REQUEST
        assert row['observation']['details']['matcher_status'] is (case in fixture.NUCLEI_GIT_MATCHED_CASES)


def test_fresh_grant_is_consumed_once(tmp_path, terminal):
    baseline.gates.test_required_grant_is_consumed_once_for_real_tool(tmp_path, terminal, 'nuclei-git-main', 1)


def test_missing_proof_stops_before_admission(tmp_path, monkeypatch):
    baseline.gates.test_missing_consumed_proof_blocks_before_nested_admission(tmp_path, monkeypatch, 'nuclei-git-main')


def test_cancel_after_native_exec_reaps_entire_tree_and_scratch(tmp_path):
    baseline.cancel_actual(tmp_path, 'nuclei-git-stalled', b'/tool/nuclei')


def test_private_inputs_descriptors_and_host_writes_are_excluded(tmp_path, monkeypatch):
    baseline.test_private_inputs_descriptors_and_host_writes_are_excluded(
        tmp_path, monkeypatch, case='nuclei-git-main')


@pytest.mark.parametrize('fault', ['noexec', 'byte_limit', 'inode_limit', 'task_limit'])
def test_relaxed_scratch_or_task_boundary_is_refused_before_exec(tmp_path, monkeypatch, fault):
    baseline.test_relaxed_scratch_or_task_boundary_is_refused_before_exec(
        tmp_path, monkeypatch, fault, case='nuclei-git-main')
