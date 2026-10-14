"""AAAA/PTR replay binds observations to capture and preserves scope separation."""

import base64
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import assessment_inspection, cli
from recon_cockpit.secure_agent import nmap_evidence as evidence
from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_dns_address_spec as spec
from recon_cockpit.secure_agent import network_tools_parser as parser
from recon_cockpit.secure_agent import network_tools_parser_runtime as parser_runtime
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_workflow as workflow
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.network_tools_lab_contract import identity
from recon_cockpit.secure_agent.session import _observation
from test_secure_network_tools_evidence import manifest
from test_secure_dns_address_parser import case_output, output
from test_secure_web_evidence import mutate_result


@pytest.fixture(autouse=True)
def portable_parser_double(monkeypatch):
    monkeypatch.setattr(parser_runtime, 'parse_isolated_tool',
        lambda tool, raw, stderr=b'', **kwargs: parser.parse_tool_output(tool, raw, stderr))
    monkeypatch.setattr(parser_runtime, '_runtime_files',
        lambda *args, **kwargs: pytest.fail('portable replay cannot execute a native parser'))


def snapshot(path):
    return {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in path.iterdir()}


def complete(path, case='dig-aaaa-ok', *, raw=None, status='succeeded'):
    tool = spec.tool_for_case(case)
    policy_file = 'dns-aaaa' if tool == spec.AAAA else 'dns-ptr'
    policy = parse_policy(json.loads(Path('examples/secure-agent-' + policy_file + '-policy.json').read_text()))
    action = parse_action(contract.action(case))
    selected = manifest(tool)
    digest = runtime.manifest_digest(selected)
    raw = case_output(case) if raw is None else raw
    truncated = len(raw) > 8192
    if truncated:
        raw, status = raw[:8192], 'output_limit'
    normalized = None
    if status == 'succeeded':
        try:
            normalized = parser.parse_tool_output(tool, raw)
        except ValueError:
            pass
    with evidence.NmapEvidenceStore(path, session_id=str(uuid4()), policy=policy, case=case,
            owned_lab=identity(case, str(uuid4())), workflow_profile='network_tools', runtime_sha256=digest) as store:
        store.record_decision(1, _observation(1, None))
        execution = store.start(action, policy, session_id=store._manifest['session_id'],
            session_step=1, backend=contract.BACKEND)
        counts = {'identity': store._manifest['owned_lab'], 'connection_count': 1, 'request_count': 1}
        value = {'status': status, 'results': [], 'tool_observation': normalized,
            'bytes_received': len(raw), 'truncated': truncated,
            'raw_output_base64': base64.b64encode(raw).decode(), 'raw_stderr_base64': '',
            'boundary_checks': dict.fromkeys(contract.BOUNDARY_FIELDS, True),
            'backend': contract.BACKEND, 'owned_lab': counts,
            'provenance': {'runtime_sha256': digest, 'runtime_manifest': selected,
                'output_sha256': hashlib.sha256(raw).hexdigest(), 'stderr_sha256': hashlib.sha256(b'').hexdigest(),
                'parser_version': spec.PARSER_VERSIONS[tool], 'exit_code': 0 if status == 'succeeded' else 1,
                'stop_reason': 'output_limit' if truncated else None}}
        store.finish(execution, value, execution_status=status)
        store.record_lab_closed({**counts, 'status': 'closed'})
        return store.finalize({'session_id': store._manifest['session_id'], 'mode': 'execute',
            'session_status': 'completed', 'stop_reason': 'coordinator_done', 'steps_attempted': 1,
            'actions_succeeded': int(status == 'succeeded'), 'output_reserved_bytes': 8192})


def assert_inconclusive_unchanged(path):
    before = snapshot(path)
    for inspect in (evidence.inspect_evidence, assessment_inspection.inspect_saved_assessment):
        report = inspect(path)
        assert report['outcome'] == 'inconclusive' and report['integrity_issues']
        assert report['metrics']['legitimate_task_completed'] is False
    assert snapshot(path) == before


@pytest.mark.parametrize('case', spec.SUCCESS_CASES)
def test_ordinary_absence_and_robustness_results_replay_with_complete_markdown(case, tmp_path, capsys):
    path = tmp_path / 'evidence'
    tool = spec.tool_for_case(case)
    field = 'address' if tool == spec.AAAA else 'target'
    report = complete(path, case)
    prefix = 'dns_aaaa_' if tool == spec.AAAA else 'dns_ptr_'
    suffix = 'name_not_found' if case.endswith('-nxdomain') else 'no_data' if case.endswith('-nodata') else 'observed'
    assert report['outcome'] == prefix + suffix and report['integrity_issues'] == []
    assert report['summary']['actions_succeeded'] == 1
    assert report['metrics'] == {'legitimate_task_completed': True, 'useful_actions_completed': 1,
        'actual_provider_calls': 0, 'actual_cost_microusd': 0, 'comparative_overhead': None}
    assert report['workflow_card'] == workflow.card_identity(case)
    assert report['workflow_card']['version'] == '31'
    assert len(report['records']) == 1 and report['records'][0]['observation']['followup_path'] is None
    details = report['finding']['tool_observation']['details']
    assert details == parser.parse_tool_output(tool, case_output(case))
    assert report['owned_lab']['closure']['connection_count'] == report['owned_lab']['closure']['request_count'] == 1
    markdown = (path / 'report.md').read_text()
    assert '## DNS address and reverse-name metadata' in markdown
    assert '| ' + field + ' | TTL |' in markdown
    assert '| query_type | `"' + spec.QUERY_TYPES[tool] + '"` |' in markdown
    assert '| status | `"' + details['status'] + '"` |' in markdown
    for row in details['records']:
        assert '| `"' + row[field] + '"` | `' + str(row['ttl']) + '` |' in markdown
    assert 'neither verifies absence' in markdown and 'no scope or follow-up authority' in markdown
    before = snapshot(path)
    assert evidence.inspect_evidence(path) == assessment_inspection.inspect_saved_assessment(path) == report
    assert cli.main(['--inspect-assessment', str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == report
    assert snapshot(path) == before


@pytest.mark.parametrize('tool', spec.TOOL_IDS)
def test_hostile_txt_is_raw_only_and_advertised_destination_cannot_select_next_action(tool, tmp_path):
    case = spec.PREFIXES[tool] + 'injected'
    path = tmp_path / 'evidence'
    report = complete(path, case)
    artifact = json.loads((path / report['records'][0]['artifact']['filename']).read_bytes())
    assert spec.HOSTILE_NOTE.encode() in base64.b64decode(artifact['raw_output_base64'])
    for name in ('report.json', 'report.md', 'evidence.jsonl'):
        assert spec.HOSTILE_NOTE.encode() not in (path / name).read_bytes()
    assert spec.FOREIGN_RECORD_BY_TOOL[tool][0] in (path / 'report.md').read_text()
    with pytest.raises(ValueError, match='invalid_network_tool_step'):
        workflow.decide(case, 2, report['records'],
            _observation(2, {'execution_status': 'succeeded', 'untrusted_result': artifact}))


@pytest.mark.parametrize('tool', spec.TOOL_IDS)
def test_report_explains_actual_metadata_and_custody_limits(tool, tmp_path):
    path = tmp_path / 'evidence'
    report = complete(path, spec.PREFIXES[tool] + 'nodata')
    text = ' '.join(report['limitations'])
    for term in ('AAAA', 'PTR', 'IPv4 TCP', 'untrusted', 'no-data', 'no IPv6 network authorization',
                 'wire capture', 'local consistency', 'reverse-to-forward', 'paid/live models'):
        assert term in text
    assert 'not a professional engagement' in text


@pytest.mark.parametrize('tool', spec.TOOL_IDS)
@pytest.mark.parametrize('mutation', [
    lambda r: r.update(tool_observation=None),
    lambda r: r['tool_observation'].update(identity_verified=True),
    lambda r: r['tool_observation'].update(semantics='verified_inventory'),
    lambda r: r['tool_observation'].update(query_name='outside.invalid.'),
    lambda r: r['tool_observation'].update(query_type='A'),
    lambda r: r['tool_observation'].update(transport='udp'),
    lambda r: r['tool_observation'].update(status='NXDOMAIN'),
    lambda r: r['tool_observation'].update(additional_txt_count=1),
    lambda r: r['tool_observation'].update(followup='outside.invalid.'),
    lambda r: r['tool_observation']['records'][0].update(ttl=61),
    lambda r: r['tool_observation']['records'].reverse(),
    lambda r: r['owned_lab'].update(request_count=0),
    lambda r: r['owned_lab'].update(request_count=2),
    lambda r: r['owned_lab'].update(connection_count=0),
    lambda r: r['owned_lab'].update(connection_count=2),
    lambda r: r['provenance'].update(exit_code=1),
    lambda r: r['provenance'].update(runtime_sha256='f' * 64),
    lambda r: r['boundary_checks'].update(forbidden_ip_blocked=False),
    lambda r: r['boundary_checks'].update(forbidden_port_blocked=False),
    lambda r: r.update(truncated=True),
])
def test_rehashed_claims_cannot_override_retained_capture_contract_and_journal(tool, mutation, tmp_path):
    path = tmp_path / 'evidence'
    complete(path, spec.PREFIXES[tool] + 'ok')
    mutate_result(path, 1, mutation)
    assert_inconclusive_unchanged(path)


@pytest.mark.parametrize('tool', spec.TOOL_IDS)
@pytest.mark.parametrize('variant', ['single', 'nodata', 'nxdomain', 'four', 'injected'])
def test_coherently_rehashed_valid_capture_must_match_original_journal(tool, variant, tmp_path):
    path = tmp_path / 'evidence'
    complete(path, spec.PREFIXES[tool] + 'ok')
    raw = case_output(spec.PREFIXES[tool] + variant)
    normalized = parser.parse_tool_output(tool, raw)
    def mutate(result):
        result.update(raw_output_base64=base64.b64encode(raw).decode(), bytes_received=len(raw),
            tool_observation=normalized)
        result['provenance']['output_sha256'] = hashlib.sha256(raw).hexdigest()
    mutate_result(path, 1, mutate)
    result = json.loads(next(path.glob('result-*.json')).read_bytes())
    events = [json.loads(line) for line in (path / 'evidence.jsonl').read_text().splitlines()]
    record = next(event['record'] for event in events if event['event_type'] == 'assessment_execution_finished')
    assert contract.parse_observation(record['action'], result, execution_status='succeeded') != record['observation']
    # The bounded planner digest does not authenticate the full result. Original
    # journal/raw comparison provides this local consistency check instead.
    assert evidence._observation_digest(1, 'succeeded', result) == record['authority_observation_sha256']
    assert_inconclusive_unchanged(path)


@pytest.mark.parametrize('tool', spec.TOOL_IDS)
@pytest.mark.parametrize('source,replacement', [('nodata', 'nxdomain'), ('nxdomain', 'nodata'), ('nodata', 'ok'), ('nxdomain', 'ok')])
def test_recordless_response_states_cannot_substitute_for_one_another(tool, source, replacement, tmp_path):
    path = tmp_path / 'evidence'
    complete(path, spec.PREFIXES[tool] + source)
    raw = case_output(spec.PREFIXES[tool] + replacement)
    def mutate(result):
        result.update(raw_output_base64=base64.b64encode(raw).decode(), bytes_received=len(raw))
        result['provenance']['output_sha256'] = hashlib.sha256(raw).hexdigest()
    mutate_result(path, 1, mutate)
    assert_inconclusive_unchanged(path)


@pytest.mark.parametrize('case', spec.NEGATIVE_CASES)
def test_invalid_or_pressure_output_is_inconclusive_after_a_recorded_request(case, tmp_path):
    path = tmp_path / 'evidence'
    report = complete(path, case)
    assert report['outcome'] == 'inconclusive' and report['integrity_issues'] == []
    assert report['metrics']['legitimate_task_completed'] is False
    assert report['metrics']['useful_actions_completed'] == 0
    assert report['owned_lab']['closure']['request_count'] == 1
    before = snapshot(path)
    assert evidence.inspect_evidence(path) == assessment_inspection.inspect_saved_assessment(path) == report
    assert snapshot(path) == before


@pytest.mark.parametrize('case', spec.SUCCESS_CASES)
def test_valid_looking_output_does_not_override_a_failed_process(case, tmp_path):
    report = complete(tmp_path / 'evidence', case, status='failed')
    assert report['outcome'] == 'inconclusive' and report['integrity_issues'] == []
    assert report['metrics']['legitimate_task_completed'] is False
    assert report['summary']['actions_succeeded'] == 0
