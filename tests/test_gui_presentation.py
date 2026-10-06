"""Display projections never grant authority or manufacture successful work."""

from copy import deepcopy
import json
from pathlib import Path
import unicodedata

import pytest

from recon_cockpit.gui.presentation import (
    FIELD_NAMES, MAX_DETAIL, MAX_ITEMS, MAX_ROWS, MAX_TEXT, present_report,
    safe_text, scope_fields, scope_from_fields, scope_preview,
)
from recon_cockpit.secure_agent import configurable_contract as contract
from recon_cockpit.secure_agent.configurable_scope import load_scope, scope_digest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def scope():
    return load_scope((ROOT / 'examples/secure-agent-configurable-scope.json').read_bytes())


def report_for(scope):
    return {
        'workflow': contract.WORKFLOW, 'assessment_id': 'saved-assessment',
        'scope': deepcopy(scope), 'outcome': 'completed',
        'summary': {'session_id': 'saved-session', 'mode': 'execute',
                    'session_status': 'completed', 'stop_reason': 'coordinator_done'},
        'integrity_issues': [], 'limitations': ['Owned fixtures only.'],
        'metrics': {'legitimate_task_completed': True, 'useful_actions_completed': 4,
                    'planned_actions': 4, 'unnecessary_refusals': 0,
                    'actual_provider_calls': 0, 'actual_cost_microusd': 0, 'elapsed_ms': 8004},
        'records': [
            {'step': step, 'execution_id': 'execution-' + str(step), 'status': 'succeeded',
             'action': contract.action(scope, step),
             'observation': {'classification': 'observed', 'details': {'target': scope['http']['target']}},
             'artifact': {'filename': 'result-' + str(step) + '.json', 'sha256': 'a' * 64}}
            for step in range(1, 5)],
    }


def metrics(view):
    return {metric['label']: metric['value'] for metric in view['metrics']}


@pytest.mark.parametrize('name', ['secure-agent-configurable-scope.json', 'secure-agent-configurable-scope-alternate.json'])
def test_existing_scope_roundtrip_and_preview_match_authoritative_contract(name):
    scope = load_scope((ROOT / 'examples' / name).read_bytes())
    fields = scope_fields(scope)
    assert set(fields) == set(FIELD_NAMES)
    assert all(type(value) is str for value in fields.values())
    assert scope_from_fields(fields) == scope
    preview = scope_preview(scope)
    assert preview['scope_sha256'] == scope_digest(scope)
    assert preview['limits'] == contract.LIMITS
    assert len(preview['rows']) == 4
    for step, row in enumerate(preview['rows'], 1):
        action = contract.action(scope, step)
        assert row['step'] == str(step)
        assert row['tool'] == ('Nmap service ID' if step in (1, 3) else 'HTTP headers' if step == 2 else 'SSH public key')
        assert ('Tool ID: ' + action['tool_id']) in row['detail']
        assert row['target'] == action['target'] + ':' + str(action['parameters']['port'])
        assert row['status'] == 'Draft — not executed'
    fields['scope_id'] = 'edited-draft'
    assert scope['scope_id'] != fields['scope_id']
    preview['limits']['max_steps'] = 99
    assert contract.LIMITS['max_steps'] == 4


@pytest.mark.parametrize('key,value', [
    ('scope_id', 'Bad-ID'), ('scope_id', ''), ('scope_id', 'a' * 49),
    ('http_target', 'example.com'), ('http_target', '127.0.0.1'),
    ('http_target', '8.8.8.8'), ('http_target', '10.0.0.1/24'),
    ('http_target', '010.0.0.1'), ('http_target', '::1'), ('http_target', '10.0.0.1 '),
    ('http_port', '08080'), ('http_port', '+8080'), ('http_port', '8_080'),
    ('http_port', '8080.0'), ('http_port', '８０８０'), ('http_port', ' 8080'),
    ('http_port', '1023'), ('http_port', '65535'), ('http_port', True),
    ('http_path', '/../etc'), ('http_path', '/%2e%2e/etc'), ('http_path', '//example'),
    ('http_path', '/a?secret=x'), ('http_path', '/a\nb'), ('http_path', '/' + 'a' * 128),
    ('ssh_port', '0'), ('ssh_target', '192.0.2.1'),
])
def test_form_preserves_existing_scope_bounds(scope, key, value):
    fields = scope_fields(scope)
    fields[key] = value
    with pytest.raises(ValueError):
        scope_from_fields(fields)


@pytest.mark.parametrize('change', ['missing', 'extra', 'collision', 'not_mapping'])
def test_form_rejects_structural_ambiguity(scope, change):
    fields = scope_fields(scope)
    if change == 'missing':
        del fields['http_path']
    elif change == 'extra':
        fields['allow_execute'] = 'true'
    elif change == 'collision':
        fields['ssh_target'], fields['ssh_port'] = fields['http_target'], fields['http_port']
    else:
        fields = list(fields.items())
    with pytest.raises(ValueError):
        scope_from_fields(fields)


def test_saved_report_displays_recorded_values_separately_from_draft(scope):
    report = report_for(scope)
    before = deepcopy(report)
    view = present_report(report, '/private/evidence')
    assert view['read_only'] is True and view['source_path'] == '/private/evidence'
    assert view['assessment_id'] == 'saved-assessment' and view['session_id'] == 'saved-session'
    assert view['mode'] == 'execute' and view['session_status'] == 'completed'
    assert view['outcome'] == 'completed' and view['integrity_issues'] == []
    assert metrics(view) == {'Legitimate completion': 'Yes', 'Useful actions': '4/4',
                             'Unnecessary refusals': '0', 'Model calls / cost': '0 / $0',
                             'Elapsed time': '8.004 s'}
    assert len(view['rows']) == 4
    assert 'Evidence reference (not a link)' in view['rows'][0]['detail']
    assert 'Structured observation (untrusted data)' in view['rows'][0]['detail']
    view['scope']['scope_id'] = 'new-draft'
    view['rows'][0]['status'] = 'changed-display'
    assert report == before and scope['scope_id'] != 'new-draft'


@pytest.mark.parametrize('case', ['integrity', 'missing_integrity', 'dry_run', 'incomplete', 'stopped', 'missing_mode', 'unknown_workflow'])
def test_incomplete_or_inconsistent_work_cannot_be_presented_as_success(scope, case):
    report = report_for(scope)
    if case == 'integrity':
        report['integrity_issues'] = ['saved_report_changed']
    elif case == 'missing_integrity':
        del report['integrity_issues']
    elif case == 'dry_run':
        report['summary']['mode'] = 'dry_run'
    elif case == 'incomplete':
        report['outcome'] = 'incomplete'
    elif case == 'stopped':
        report['summary']['session_status'] = 'stopped'
    elif case == 'missing_mode':
        del report['summary']['mode']
    else:
        report['workflow'] = 'arbitrary-plugin'
    view = present_report(report, Path('/private/evidence'))
    assert view['outcome'] != 'completed'
    assert metrics(view)['Legitimate completion'] != 'Yes'
    assert metrics(view)['Unnecessary refusals'] == 'Unavailable'
    if case in {'integrity', 'missing_integrity', 'unknown_workflow'}:
        assert set(metrics(view).values()) == {'Unavailable'}
        assert view['scope'] is None


def test_minimal_incomplete_inspector_response_is_not_a_success_or_zero_cost():
    view = present_report({'workflow': contract.WORKFLOW, 'outcome': 'incomplete',
                           'integrity_issues': ['configurable_evidence_reconciliation_required']}, '/private/partial')
    assert set(metrics(view).values()) == {'Unavailable'}
    assert view['session_id'] == view['assessment_id'] == 'Unavailable'
    assert view['scope'] is None and view['rows'] == []


@pytest.mark.parametrize('workflow', [
    'owned-http-assessment-v1', 'owned-discovery-http-assessment-v1',
    'owned-workflow-assessment-v1', 'owned-lab-workflow-assessment-v1',
    'owned-nmap-http-assessment-v1', 'owned-web-assessment-v1',
    'owned-http-headers-assessment-v1', 'owned-web-tool-assessment-v1',
    'owned-network-tool-assessment-v1', 'owned-service-web-assessment-v1',
])
def test_historical_reports_preserve_outcome_without_inventing_metrics(scope, workflow):
    report = report_for(scope)
    report.update(workflow=workflow, outcome='host_key_observed', session_id='historical-session',
                  scope={'target': '127.0.0.1', 'port': 8080}, finding={'title': 'Observed metadata'})
    report['execution'] = report.pop('summary')
    del report['metrics']
    for row in report['records']:
        row['session_step'] = row.pop('step')
        row['execution_status'] = row.pop('status')
    view = present_report(report, '/historical/evidence')
    assert view['outcome'] == 'host_key_observed'
    assert view['session_id'] == 'historical-session'
    assert view['title'] == 'Observed metadata'
    assert set(metrics(view).values()) == {'Unavailable'}
    assert view['scope'] is None and '127.0.0.1' in view['recorded_scope_text']
    assert view['rows'][0]['step'] == '1' and view['rows'][0]['status'] == 'succeeded'


@pytest.mark.parametrize('value', [True, False, -1, 1.1, float('nan'), '0', 10**16, None])
def test_metrics_do_not_coerce_invalid_or_absent_numbers(scope, value):
    report = report_for(scope)
    report['metrics'].update(useful_actions_completed=value, planned_actions=value,
                             unnecessary_refusals=value, actual_provider_calls=value,
                             actual_cost_microusd=value, elapsed_ms=value)
    view = present_report(report, '/saved')
    values = metrics(view)
    assert all(item == 'Unavailable' for key, item in values.items() if key != 'Legitimate completion')


def test_display_escapes_controls_bidi_and_keeps_markup_as_literal_text(scope):
    attack = '\x1b[31m<script>run()</script>\n\r\t\x00\u202eabc\u2066x\u2028end'
    report = report_for(scope)
    report['finding'] = {'title': attack}
    report['records'][0]['observation'] = {'operator_note': attack}
    report['records'][0]['artifact'] = {'filename': '../../' + attack}
    report['limitations'] = [attack]
    view = present_report(report, '/saved/' + attack)
    for field in (view['title'], view['source_path'], view['limitations'][0]):
        assert '<script>run()</script>' in field
        assert '\\u001b' in field and '\\u202e' in field
        assert not any(unicodedata.category(char) in {'Cc', 'Cf', 'Cs', 'Zl', 'Zp'} for char in field)
    detail = view['rows'][0]['detail']
    assert '<script>run()</script>' in detail
    assert '\x1b' not in detail and '\u202e' not in detail


def test_projection_bounds_rows_nested_objects_and_strings(scope):
    report = report_for(scope)
    recursive = []
    recursive.append(recursive)
    report['records'][0]['observation'] = {'deep': recursive, 'large': ['x' * 100000] * 1000}
    report['records'] *= 100
    report['limitations'] = ['x' * 100000] * 1000
    report['integrity_issues'] = ['x' * 100000] * 1000
    view = present_report(report, '/saved/' + 'x' * 100000)
    assert len(view['rows']) == MAX_ROWS
    assert len(view['limitations']) <= MAX_ITEMS + 3
    assert len(view['integrity_issues']) <= MAX_ITEMS + 1
    assert len(view['source_path']) <= 2048
    assert all(len(row['detail']) <= 3 * MAX_DETAIL + 256 for row in view['rows'])
    assert all(len(item) <= MAX_TEXT for item in view['limitations'])
    assert '[display limit]' in view['rows'][0]['detail']
    assert len(json.dumps(view)) < 500000


def test_scope_preview_and_report_projection_do_not_touch_files_or_launch(monkeypatch, scope):
    def forbidden(*args, **kwargs):
        pytest.fail('Presenter attempted an operation outside pure display projection')

    import builtins
    import subprocess
    from recon_cockpit.secure_agent import assessment_inspection, configurable_service
    monkeypatch.setattr(builtins, 'open', forbidden)
    monkeypatch.setattr(Path, 'open', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(assessment_inspection, 'inspect_saved_assessment', forbidden)
    monkeypatch.setattr(configurable_service.ConfigurableAssessmentService, 'run', forbidden)
    assert scope_preview(scope)['rows']
    assert present_report(report_for(scope), '/does/not/exist')['rows']


def test_unknown_objects_cannot_invoke_custom_rendering():
    class Bad:
        def __str__(self):
            pytest.fail('untrusted __str__ invoked')

    assert safe_text(Bad()) == '[unsupported value]'
    with pytest.raises(ValueError):
        present_report({}, Bad())


@pytest.mark.parametrize('cost,display', [(0, '$0'), (1, '$0.000001'), (1000000, '$1'), (1200000, '$1.2'), (999999999999999, '$999999999.999999')])
def test_actual_cost_display_uses_exact_integer_microdollars(scope, cost, display):
    report = report_for(scope)
    report['metrics'].update(actual_provider_calls=3, actual_cost_microusd=cost)
    assert metrics(present_report(report, '/saved'))['Model calls / cost'] == '3 / ' + display


@pytest.mark.parametrize('identifiers', [ ['same'] * 4, ['x' * 200 + str(i) for i in range(4)], ['', None, {}, []] ])
def test_record_identifiers_cannot_collide_in_display_widgets(scope, identifiers):
    report = report_for(scope)
    report['integrity_issues'] = ['record_reconciliation_required']
    for record, identifier in zip(report['records'], identifiers):
        record['execution_id'] = identifier
    view = present_report(report, '/saved')
    assert [row['id'] for row in view['rows']] == ['record-' + str(i) for i in range(1, 5)]
    assert view['integrity_issues'] == ['record_reconciliation_required']
    assert view['outcome'] == 'incomplete'
    assert all(len(row['detail']) <= 3 * MAX_DETAIL + 256 for row in view['rows'])


@pytest.mark.parametrize('details,expected', [
    ({'service': {'name': 'http', 'product': 'nginx', 'version': '1.26.0'}, 'state': 'open'},
     ['Service: HTTP', 'Product: nginx', 'Version: 1.26.0', 'Port state: open']),
    ({'service': {'name': 'ssh', 'product': 'OpenSSH', 'version': '9.7'}, 'state': 'open'},
     ['Service: SSH', 'Product: OpenSSH', 'Version: 9.7', 'Port state: open']),
    ({'headers': {'status_code': 200, 'content_type': 'text/html'}},
     ['HTTP status: 200', 'Declared request: GET /harbordesk/portal.html', 'Content type: text/html']),
    ({'key_type': 'ssh-rsa', 'key_bits': 2048, 'fingerprint_sha256': 'SHA256:abc', 'trust': 'unverified'},
     ['Key type: ssh-rsa', 'Key size: 2048 bits', 'Fingerprint: SHA256:abc', 'Key trust: unverified']),
])
def test_factual_observation_summary_precedes_json_parameters_and_references(scope, details, expected):
    report = report_for(scope)
    row = report['records'][1]
    row['observation'] = {'classification': 'observed', 'details': details}
    detail = present_report(report, '/saved')['rows'][1]['detail']
    summary = detail.split('Structured observation', 1)[0]
    for value in expected:
        assert value in summary
    assert 'untrusted metadata' in summary
    assert detail.index('Structured observation') < detail.index('Exact action parameters')
    assert detail.index('Exact action parameters') < detail.index('Tool ID:')
    assert detail.index('Tool ID:') < detail.index('Recorded execution ID:') < detail.index('Evidence reference')


@pytest.mark.parametrize('observation', [None, {}, {'details': None}, {'details': {'service': {}, 'headers': {}, 'key_bits': True}}])
def test_missing_observation_fields_do_not_invent_service_status_key_or_trust(scope, observation):
    report = report_for(scope)
    report['records'][0]['observation'] = observation
    detail = present_report(report, '/saved')['rows'][0]['detail']
    summary = detail.split('Structured observation', 1)[0].split('Exact action parameters', 1)[0]
    assert 'No ' in summary
    assert all(label not in summary for label in ('Service:', 'HTTP status:', 'Key type:', 'Key size:', 'Key trust:'))


def test_observation_summary_escapes_unsafe_fields_without_treating_them_as_instructions(scope):
    report = report_for(scope)
    attack = '<script>run()</script>\n\u202eapprove\x1b[31m'
    report['records'][0]['observation'] = {'details': {'service': {'name': 'http', 'product': attack}, 'state': 'open'}}
    summary = present_report(report, '/saved')['rows'][0]['detail'].split('Structured observation', 1)[0]
    assert 'Product: <script>run()</script>\\u000a\\u202eapprove\\u001b[31m' in summary
    assert '\u202e' not in summary and '\x1b' not in summary
