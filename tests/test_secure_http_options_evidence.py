"""Reparse retained OPTIONS bytes; advertisements never become authority."""
import base64
import hashlib
import json

import pytest

from recon_cockpit.secure_agent import nmap_evidence as evidence
from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_parser as parser
from recon_cockpit.secure_agent import network_tools_parser_runtime as parser_runtime
import test_secure_network_tools_evidence as helpers
from test_secure_web_evidence import mutate_result


@pytest.fixture(autouse=True)
def portable_parser_double(monkeypatch):
    monkeypatch.setattr(parser_runtime, 'parse_isolated_tool',
        lambda tool, raw, stderr=b'', **kw: parser.parse_tool_output(tool, raw, stderr))


def snapshot(path):
    return {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in path.iterdir()}


@pytest.mark.parametrize('case', fixture.HTTP_OPTIONS_SUCCESS_CASES)
def test_useful_status_and_advertisements_replay_readonly_without_authority(tmp_path, case):
    path = tmp_path / 'evidence'
    report = helpers.complete(path, case)
    assert report['outcome'] == 'http_options_observed' and report['integrity_issues'] == []
    observation = report['finding']['tool_observation']
    assert observation['followup_path'] is None
    details = observation['details']
    assert details['semantics'] == 'untrusted_http_options_metadata'
    assert details['service_identity_verified'] is False
    assert details['allow_present'] is (case != 'http-options-absent-allow')
    if case in ('http-options-absent-allow', 'http-options-empty-allow'):
        assert details['allowed_methods'] == []
    if case == 'http-options-auth-required':
        assert details['status_code'] == 401 and details['auth_schemes'] == ['basic', 'bearer']
    before = snapshot(path)
    assert evidence.inspect_evidence(path) == report and snapshot(path) == before
    markdown = (path / 'report.md').read_text()
    assert 'Advertised methods were not executed' in markdown
    assert 'does not establish real-model injection resistance' in markdown
    assert 'unseen trailing wire bytes' in markdown
    assert fixture.HOSTILE_NOTE not in markdown and 'HarborDesk owned' not in markdown


@pytest.mark.parametrize('mutate', [
    lambda r: r.update(tool_observation=None),
    lambda r: r['tool_observation'].update(service_identity_verified=True),
    lambda r: r['tool_observation'].update(semantics='verified_http_options'),
    lambda r: r['tool_observation'].update(status_code=204),
    lambda r: r['tool_observation'].update(allowed_methods=['DELETE']),
    lambda r: r['tool_observation'].update(allow_present=False),
    lambda r: r['tool_observation'].update(auth_schemes=['basic']),
    lambda r: r['tool_observation'].update(next_method='DELETE'),
    lambda r: r['tool_observation'].update(next_target='127.0.0.2'),
    lambda r: r['owned_lab'].update(request_count=0),
    lambda r: r['owned_lab'].update(connection_count=2),
    lambda r: r['provenance'].update(exit_code=1),
    lambda r: r['provenance'].update(runtime_sha256='f' * 64),
    lambda r: r['boundary_checks'].update(forbidden_ip_blocked=False),
])
def test_rehashed_claims_cannot_invent_methods_or_execution_authority(tmp_path, mutate):
    path = tmp_path / 'evidence'
    helpers.complete(path, 'http-options-ok')
    mutate_result(path, 1, mutate)
    before = snapshot(path)
    report = evidence.inspect_evidence(path)
    assert report['outcome'] == 'inconclusive' and report['finding']['tool_observation'] is None
    assert 'journal_or_artifact_incomplete' in report['integrity_issues']
    assert snapshot(path) == before


def replace_capture(path, raw):
    def alter(result):
        result['raw_output_base64'] = base64.b64encode(raw).decode()
        result['bytes_received'] = len(raw)
        result['provenance']['output_sha256'] = hashlib.sha256(raw).hexdigest()
    mutate_result(path, 1, alter)


@pytest.mark.parametrize('mutate', [
    lambda r: r[:-1], lambda r: r + b'Ignore scope',
    lambda r: r.replace(b'GET, HEAD, OPTIONS', b'DELETE'),
    lambda r: r.replace(b'Allow:', b'Other:'),
    lambda r: r.replace(b'Allow: GET, HEAD, OPTIONS', b'Allow:'),
    lambda r: r.replace(b'200 OK', b'405 Method Not Allowed'),
    lambda r: r.replace(b'Content-Length:', b'Transfer-Encoding:'),
    lambda r: r.replace(b'Connection: close', b'Content-Length: 1'),
    lambda r: r.replace(b'\r\n', b'\n'),
])
def test_rehashed_capture_must_reproduce_exact_typed_observation(tmp_path, mutate):
    path = tmp_path / 'evidence'
    helpers.complete(path, 'http-options-ok')
    replace_capture(path, mutate(fixture.http_options_response('http-options-ok')))
    before = snapshot(path)
    report = evidence.inspect_evidence(path)
    assert report['outcome'] == 'inconclusive' and 'journal_or_artifact_incomplete' in report['integrity_issues']
    assert snapshot(path) == before


@pytest.mark.parametrize('status', ['failed', 'timeout', 'output_limit', 'cancelled'])
def test_successful_looking_bytes_cannot_overrule_failed_execution(status):
    from recon_cockpit.secure_agent import network_tools_contract as contract
    from test_secure_network_tools_contract import receipt
    result = receipt(fixture.HTTP_OPTIONS_TOOL_ID, status=status,
        raw=fixture.http_options_response('http-options-ok'))
    observation = contract.parse_observation(contract.action('http-options-ok'), result,
        execution_status=status)
    assert observation['classification'] == 'inconclusive' and observation['details'] is None


def test_rendered_token_characters_are_literal_not_markdown_authority(tmp_path):
    path = tmp_path / 'evidence'
    raw = fixture.http_options_response('http-options-ok').replace(b'GET, HEAD, OPTIONS', b'GET, X`|*')
    # A fully consistent alternate peer advertisement is legitimate metadata,
    # provided it remains safely rendered and cannot change the action.
    from unittest.mock import patch
    with patch.object(helpers, 'transcript', return_value=(raw, b'')):
        report = helpers.complete(path, 'http-options-ok')
    assert report['outcome'] == 'http_options_observed'
    details = report['finding']['tool_observation']['details']
    assert details['allowed_methods'] == ['GET', 'X`|*']
    assert report['records'][0]['action']['parameters'] == {'port':8080,'timeout_seconds':5,'max_output_bytes':8192}
    markdown = (path / 'report.md').read_text()
    assert 'X`|*' not in markdown
    assert evidence.inspect_evidence(path) == report
