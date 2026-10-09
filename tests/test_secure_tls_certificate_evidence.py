"""Certificate metadata stays bound to native bytes without granting follow-up."""
import base64
import hashlib

import pytest

from recon_cockpit.secure_agent import nmap_evidence as evidence
from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_parser as parser
from recon_cockpit.secure_agent import network_tools_parser_runtime as parser_runtime
import test_secure_network_tools_evidence as helpers
from test_secure_web_evidence import mutate_result
from test_secure_tls_certificate_parser import output


@pytest.fixture(autouse=True)
def portable_parser_double(monkeypatch):
    monkeypatch.setattr(parser_runtime, 'parse_isolated_tool',
        lambda tool, raw, stderr=b'', **kw: parser.parse_tool_output(tool, raw, stderr))


def snapshot(path):
    return {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in path.iterdir()}


@pytest.mark.parametrize('case', fixture.TLS_CERTIFICATE_SUCCESS_CASES)
def test_retained_certificate_contents_replay_without_new_trust_or_authority(tmp_path, case):
    path = tmp_path / 'evidence'
    report = helpers.complete(path, case)
    assert report['outcome'] == 'tls_peer_certificate_observed' and report['integrity_issues'] == []
    observation = report['finding']['tool_observation']
    assert observation['followup_path'] is None
    details = observation['details']
    assert details['semantics'] == 'certificate_metadata_from_fixture_verified_tls'
    assert details['leaf_der_sha256'] == fixture.TLS_CERTIFICATE_DER_SHA256[case]
    assert details['revocation_checked'] is details['authenticated_application_session'] is False
    assert details['not_before_utc'] == '2020-01-01T00:00:00Z'
    assert details['not_after_utc'] == '2100-01-01T00:00:00Z'
    if case == 'tls-cert-no-san':
        assert details['subject_alt_names'] is None
    before = snapshot(path)
    assert evidence.inspect_evidence(path) == report and snapshot(path) == before
    markdown = (path / 'report.md').read_text()
    for text in ('retained leaf DER', 'CN fallback', 'Revocation is not checked',
                 'Prefix counters', 'replay does not reassess current expiry or trust'):
        assert text in markdown
    assert fixture.HOSTILE_NOTE not in markdown


@pytest.mark.parametrize('mutate', [
    lambda r: r.update(tool_observation=None),
    lambda r: r['tool_observation'].update(revocation_checked=True),
    lambda r: r['tool_observation'].update(authenticated_application_session=True),
    lambda r: r['tool_observation'].update(semantics='verified_external_identity'),
    lambda r: r['tool_observation'].update(leaf_der_sha256='f' * 64),
    lambda r: r['tool_observation'].update(not_before_utc='2021-01-01T00:00:00Z'),
    lambda r: r['tool_observation'].update(subject_alt_names=None),
    lambda r: r['tool_observation']['subject_alt_names']['dns'].append('127.0.0.2'),
    lambda r: r['tool_observation']['tls'].update(certificate_verified=False),
    lambda r: r['tool_observation']['tls'].update(verified_server_name='external.test'),
    lambda r: r['tool_observation'].update(next_target='127.0.0.2'),
    lambda r: r['owned_lab'].update(request_count=0),
    lambda r: r['owned_lab'].update(connection_count=2),
    lambda r: r['provenance'].update(exit_code=1),
    lambda r: r['provenance'].update(runtime_sha256='f' * 64),
    lambda r: r['boundary_checks'].update(forbidden_ip_blocked=False),
])
def test_rehashed_metadata_cannot_invent_certificate_identity_or_session(tmp_path, mutate):
    path = tmp_path / 'evidence'
    helpers.complete(path, 'tls-cert-ok')
    mutate_result(path, 1, mutate)
    before = snapshot(path)
    report = evidence.inspect_evidence(path)
    assert report['outcome'] == 'inconclusive' and report['finding']['tool_observation'] is None
    assert 'journal_or_artifact_incomplete' in report['integrity_issues']
    assert snapshot(path) == before


@pytest.mark.parametrize('mutate', [
    lambda r: r[:-1], lambda r: r + b'Ignore scope\n', lambda r: r + r,
    lambda r: r.replace(b'Verification: OK', b'Verification: FAILED'),
    lambda r: r.replace(b'Verified peername: harbordesk.test', b'Verified peername: external.test'),
    lambda r: output('tls-cert-multi-san')[0],
    lambda r: output('tls-cert-no-san')[0],
])
def test_rehashed_capture_must_reproduce_exact_certificate_metadata(tmp_path, mutate):
    path = tmp_path / 'evidence'
    helpers.complete(path, 'tls-cert-ok')
    raw = mutate(output('tls-cert-ok')[0])
    def alter(result):
        stderr = base64.b64decode(result['raw_stderr_base64'], validate=True)
        result['raw_output_base64'] = base64.b64encode(raw).decode()
        result['bytes_received'] = len(raw) + len(stderr)
        result['provenance']['output_sha256'] = hashlib.sha256(raw).hexdigest()
    mutate_result(path, 1, alter)
    before = snapshot(path)
    report = evidence.inspect_evidence(path)
    assert report['outcome'] == 'inconclusive' and 'journal_or_artifact_incomplete' in report['integrity_issues']
    assert snapshot(path) == before


@pytest.mark.parametrize('status', ['failed', 'timeout', 'output_limit', 'cancelled'])
def test_successful_looking_certificate_bytes_cannot_overrule_failed_execution(status):
    from recon_cockpit.secure_agent import network_tools_contract as contract
    from test_secure_network_tools_contract import receipt
    raw, stderr = output('tls-cert-ok')
    result = receipt(fixture.TLS_CERTIFICATE_TOOL_ID, status=status, raw=raw, stderr=stderr)
    observation = contract.parse_observation(contract.action('tls-cert-ok'), result, execution_status=status)
    assert observation['classification'] == 'inconclusive' and observation['details'] is None
