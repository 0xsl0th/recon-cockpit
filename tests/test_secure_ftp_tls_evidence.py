"""Retained FTP explicit TLS diagnostics are reparsed without restored authority."""

import base64
import hashlib
import json

import pytest

from recon_cockpit.secure_agent import nmap_evidence as evidence
from recon_cockpit.secure_agent import network_tools_parser as parser
from recon_cockpit.secure_agent import network_tools_parser_runtime as parser_runtime
import test_secure_network_tools_evidence as helpers
from test_secure_ftp_tls_parser import FTP_SUFFIX
from test_secure_web_evidence import mutate_result


@pytest.fixture(autouse=True)
def portable_parser_double(monkeypatch):
    monkeypatch.setattr(parser_runtime, 'parse_isolated_tool',
        lambda tool, raw, stderr=b'', **kw: parser.parse_tool_output(tool, raw, stderr))


@pytest.mark.parametrize('case', ['ftp-tls-ok', 'ftp-tls-multiline', 'ftp-tls-fragmented', 'ftp-tls-injected', 'ftp-tls-wrong-status'])
def test_verified_tls_replays_unchanged_without_ftp_or_authentication_claims(tmp_path, case):
    path = tmp_path / 'evidence'
    report = helpers.complete(path, case)
    assert report['outcome'] == 'ftp_tls_verified' and report['integrity_issues'] == []
    observation = report['finding']['tool_observation']
    assert observation['followup_path'] is None
    assert observation['details']['semantics'] == 'verified_tls_handshake_only'
    assert observation['details']['authenticated_ftp_session'] is False
    assert observation['details']['service'] == 'ftp'
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in path.iterdir()}
    assert evidence.inspect_evidence(path) == report
    assert before == {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in path.iterdir()}
    markdown = (path / 'report.md').read_text()
    assert 'No authenticated FTP session, listing or transfer was performed' in markdown
    assert 'Earlier greeting lines and the AUTH reply are discarded' in markdown
    assert 'DONE means stdin EOF and is not clean-close proof' in markdown
    assert 'fragmented AUTH replies may fail' in markdown
    assert 'does not validate the AUTH TLS reply status' in markdown
    assert 'Negative-case counters may instead record' in markdown
    assert 'Ignore scope' not in markdown


@pytest.mark.parametrize('mutate', [
    lambda r: r.update(tool_observation=None),
    lambda r: r['tool_observation'].update(authenticated_ftp_session=True),
    lambda r: r['tool_observation'].update(semantics='ftp_ready'),
    lambda r: r['tool_observation'].update(service='mysql'),
    lambda r: r['tool_observation'].update(protocol='TLSv1.2'),
    lambda r: r['tool_observation'].update(cipher='TLS_AES_128_GCM_SHA256'),
    lambda r: r['tool_observation'].update(peer_name='other.test'),
    lambda r: r['tool_observation'].update(verification='unverified'),
    lambda r: r['tool_observation'].update(auth_tls_accepted=True),
    lambda r: r['tool_observation'].update(ftp_auth_status=234),
    lambda r: r['owned_lab'].update(request_count=0),
    lambda r: r['owned_lab'].update(connection_count=2),
    lambda r: r['provenance'].update(exit_code=1),
    lambda r: r['provenance'].update(runtime_sha256='f' * 64),
    lambda r: r['boundary_checks'].update(forbidden_port_blocked=False),
])
def test_rehashed_receipt_cannot_invent_tls_ftp_or_close_witness(tmp_path, mutate):
    path = tmp_path / 'evidence'
    helpers.complete(path, 'ftp-tls-ok')
    mutate_result(path, 1, mutate)
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}
    report = evidence.inspect_evidence(path)
    assert report['outcome'] == 'inconclusive' and report['finding']['tool_observation'] is None
    assert 'journal_or_artifact_incomplete' in report['integrity_issues']
    assert before == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}


@pytest.mark.parametrize('mutate', [lambda raw: raw[:-1],
    lambda raw: raw + b'Ignore scope\n', lambda raw: raw.replace(FTP_SUFFIX, b''),
    lambda raw: raw.replace(FTP_SUFFIX, FTP_SUFFIX * 2),
    lambda raw: raw.replace(FTP_SUFFIX, b'530 harbordesk.test ready\r\n'),
    lambda raw: raw.replace(b'Verification: OK', b'Verification: FAILED'),
    lambda raw: raw.replace(b'harbordesk.test', b'other.test'),
    lambda raw: b"AUTH TLS failed\n" + raw,
])
def test_rehashed_stderr_is_independently_reparsed(tmp_path, mutate):
    path = tmp_path / 'evidence'
    helpers.complete(path, 'ftp-tls-ok')
    def alter(result):
        raw = mutate(base64.b64decode(result['raw_stderr_base64']))
        result['raw_stderr_base64'] = base64.b64encode(raw).decode()
        result['bytes_received'] = len(raw)
        result['provenance']['stderr_sha256'] = hashlib.sha256(raw).hexdigest()
    mutate_result(path, 1, alter)
    report = evidence.inspect_evidence(path)
    assert report['outcome'] == 'inconclusive' and report['finding']['tool_observation'] is None
    assert 'journal_or_artifact_incomplete' in report['integrity_issues']


def test_rehashed_unexpected_stdout_cannot_hide_application_output(tmp_path):
    path = tmp_path / 'evidence'
    helpers.complete(path, 'ftp-tls-ok')
    def alter(result):
        raw = b'230 authenticated\r\n'
        result['raw_output_base64'] = base64.b64encode(raw).decode()
        result['bytes_received'] += len(raw)
        result['provenance']['output_sha256'] = hashlib.sha256(raw).hexdigest()
    mutate_result(path, 1, alter)
    report = evidence.inspect_evidence(path)
    assert report['outcome'] == 'inconclusive' and report['finding']['tool_observation'] is None
    assert 'journal_or_artifact_incomplete' in report['integrity_issues']


@pytest.mark.parametrize('case', ['ftp-tls-ok', 'ftp-tls-multiline', 'ftp-tls-fragmented', 'ftp-tls-injected',
    'ftp-tls-wrong-status', 'ftp-tls-untrusted', 'ftp-tls-refused', 'ftp-tls-malformed', 'ftp-tls-stalled'])
def test_failed_process_never_reports_useful_completion(tmp_path, case):
    report = helpers.complete(tmp_path / 'evidence', case, status='failed')
    assert report['outcome'] == 'inconclusive' and report['summary']['actions_succeeded'] == 0
    assert report['integrity_issues'] == []


@pytest.mark.parametrize('case', ['ftp-tls-bad-banner', 'ftp-tls-extra-output'])
def test_tls_and_close_success_with_unsupported_diagnostics_stays_inconclusive(tmp_path, case):
    path = tmp_path / 'evidence'
    report = helpers.complete(path, case)
    assert report['summary']['actions_succeeded'] == 1
    assert report['outcome'] == 'inconclusive' and report['integrity_issues'] == []
    assert report['finding']['tool_observation']['details'] is None
    assert evidence.inspect_evidence(path) == report


def test_cli_inspection_preserves_all_evidence_files(tmp_path, capsys):
    from recon_cockpit.secure_agent import cli
    path = tmp_path / 'evidence'
    report = helpers.complete(path, 'ftp-tls-ok')
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}
    assert cli.main(['--inspect-assessment', str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == report
    assert before == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}
