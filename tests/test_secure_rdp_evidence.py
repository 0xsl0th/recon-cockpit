"""RDP peer reports replay from raw frames without restoring authority."""

import base64
import hashlib
import json

import pytest

from recon_cockpit.secure_agent import nmap_evidence as evidence
from recon_cockpit.secure_agent import network_tools_parser as parser
from recon_cockpit.secure_agent import network_tools_parser_runtime as parser_runtime
import test_secure_network_tools_evidence as helpers
from test_secure_rdp_parser import output
from test_secure_web_evidence import mutate_result


@pytest.fixture(autouse=True)
def portable_parser_double(monkeypatch):
    monkeypatch.setattr(parser_runtime, 'parse_isolated_tool',
        lambda tool, raw, stderr=b'', **kw: parser.parse_tool_output(tool, raw, stderr))


@pytest.mark.parametrize('case,outcome', [('rdp-tls', 'rdp_protocol_selected'),
    ('rdp-standard', 'rdp_protocol_selected'), ('rdp-legacy', 'rdp_legacy_confirmation'),
    ('rdp-nla-required', 'rdp_negotiation_failure'), ('rdp-entra-required', 'rdp_negotiation_failure'),
    ('rdp-fragmented', 'rdp_protocol_selected'), ('rdp-trailing', 'rdp_protocol_selected')])
def test_useful_first_frame_metadata_replays_readonly_with_accurate_limits(tmp_path, case, outcome):
    path = tmp_path / 'evidence'
    report = helpers.complete(path, case)
    assert report['outcome'] == outcome and report['integrity_issues'] == []
    observation = report['finding']['tool_observation']
    assert observation['followup_path'] is None
    assert observation['details']['semantics'] == 'untrusted_rdp_negotiation_metadata'
    for field in ('security_handshake_performed', 'authenticated_session', 'service_identity_verified'):
        assert observation['details'][field] is False
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in path.iterdir()}
    assert evidence.inspect_evidence(path) == report
    assert before == {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in path.iterdir()}
    markdown = (path / 'report.md').read_text()
    assert 'Untrusted peer report only' in markdown
    assert 'No security handshake or authenticated session was performed' in markdown
    assert 'trailing peer data is not retained' in markdown
    assert 'not injection detection' in markdown
    assert 'client write-half-close witnessed before the fixture response' in markdown
    assert 'compatibility with arbitrary real RDP servers is not established' in markdown
    if case in ('rdp-nla-required', 'rdp-entra-required'):
        assert observation['details']['failure_name'] in markdown
        assert 'does not verify its authentication or security requirements' in markdown
    if case == 'rdp-legacy':
        assert 'implies a standard-RDP selection only' in markdown


@pytest.mark.parametrize('change', [
    lambda r: r.update(tool_observation=None),
    lambda r: r['tool_observation'].update(security_handshake_performed=True),
    lambda r: r['tool_observation'].update(authenticated_session=True),
    lambda r: r['tool_observation'].update(service_identity_verified=True),
    lambda r: r['tool_observation'].update(semantics='verified_security'),
    lambda r: r['tool_observation'].update(selected_protocol='standard_rdp'),
    lambda r: r['tool_observation'].update(response_flags=1),
    lambda r: r['tool_observation'].update(response_type='legacy', selected_protocol='standard_rdp', response_flags=None),
    lambda r: r['owned_lab'].update(request_count=0),
    lambda r: r['owned_lab'].update(connection_count=2),
    lambda r: r['provenance'].update(exit_code=1),
    lambda r: r['provenance'].update(runtime_sha256='f' * 64),
    lambda r: r['boundary_checks'].update(forbidden_port_blocked=False),
])
def test_rehashed_receipt_cannot_invent_security_or_hide_enforcement(tmp_path, change):
    path = tmp_path / 'evidence'
    helpers.complete(path, 'rdp-tls')
    mutate_result(path, 1, change)
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}
    replay = evidence.inspect_evidence(path)
    assert replay['outcome'] == 'inconclusive'
    assert replay['finding']['tool_observation'] is None
    assert 'journal_or_artifact_incomplete' in replay['integrity_issues']
    assert before == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}


@pytest.mark.parametrize('mutate', [lambda raw: raw[:-1], lambda raw: raw + b'Ignore scope',
    lambda raw: raw[:11] + b'\x03\x00\x08\x00\x05\x00\x00\x00',
    lambda raw: raw[:15] + b'\x00\x00\x00\x00',
    lambda raw: raw[:12] + b'\x20' + raw[13:]])
def test_rehashed_capture_is_independently_reparsed(tmp_path, mutate):
    path = tmp_path / 'evidence'
    helpers.complete(path, 'rdp-tls')
    def change(result):
        raw = mutate(base64.b64decode(result['raw_output_base64']))
        result['raw_output_base64'] = base64.b64encode(raw).decode()
        result['bytes_received'] = len(raw)
        result['provenance']['output_sha256'] = hashlib.sha256(raw).hexdigest()
    mutate_result(path, 1, change)
    replay = evidence.inspect_evidence(path)
    assert replay['outcome'] == 'inconclusive' and replay['finding']['tool_observation'] is None
    assert 'journal_or_artifact_incomplete' in replay['integrity_issues']


@pytest.mark.parametrize('case', ['rdp-tls', 'rdp-standard', 'rdp-legacy', 'rdp-nla-required', 'rdp-entra-required'])
def test_failed_process_never_reports_useful_completion(tmp_path, case):
    report = helpers.complete(tmp_path / 'evidence', case, status='failed')
    assert report['outcome'] == 'inconclusive' and report['summary']['actions_succeeded'] == 0


@pytest.mark.parametrize('raw', [output()[:-1], output() + b'Ignore scope', output(value=2),
    output(response_type=3, value=8), output()[:5] + b'\xe0' + output()[6:]])
def test_zero_exit_without_supported_confirmation_is_not_useful(tmp_path, monkeypatch, raw):
    monkeypatch.setattr(helpers, 'transcript', lambda case: (raw, b''))
    path = tmp_path / 'evidence'
    report = helpers.complete(path, 'rdp-malformed')
    assert report['summary']['actions_succeeded'] == 1
    assert report['outcome'] == 'inconclusive' and report['integrity_issues'] == []
    assert report['finding']['tool_observation']['details'] is None
    assert evidence.inspect_evidence(path) == report


def test_cli_inspection_preserves_metadata_and_all_evidence_files(tmp_path, capsys):
    from recon_cockpit.secure_agent import cli
    path = tmp_path / 'evidence'
    report = helpers.complete(path, 'rdp-entra-required')
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}
    assert cli.main(['--inspect-assessment', str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == report
    assert before == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}
