"""Retained SSH advertisements cannot grant algorithm, target or session authority."""
import base64
import hashlib
from unittest.mock import patch

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


@pytest.mark.parametrize('case', fixture.SSH_ALGORITHMS_SUCCESS_CASES)
def test_advertisements_preserve_order_direction_and_unverified_meaning(tmp_path, case):
    path = tmp_path / 'evidence'
    report = helpers.complete(path, case)
    assert report['outcome'] == 'ssh_algorithm_advertisements_observed' and report['integrity_issues'] == []
    observation = report['finding']['tool_observation']
    assert observation['followup_path'] is None
    details = observation['details']
    assert details['semantics'] == 'untrusted_ssh_algorithm_advertisements'
    assert details['key_exchange_completed'] is details['authenticated_session'] is details['service_identity_verified'] is False
    assert details['server_identification'] == 'SSH-2.0-HarborDesk_1'
    assert details['first_kex_packet_follows'] is (case == 'ssh-algos-guessed')
    if case == 'ssh-algos-directional':
        assert details['algorithms']['encryption_algorithms_client_to_server'] != details['algorithms']['encryption_algorithms_server_to_client']
    if case == 'ssh-algos-legacy':
        assert details['algorithms']['kex_algorithms'] == ['diffie-hellman-group14-sha1']
    before = snapshot(path)
    assert evidence.inspect_evidence(path) == report and snapshot(path) == before
    markdown = (path / 'report.md').read_text()
    assert 'No algorithm was negotiated' in markdown
    assert 'does not establish real-model injection resistance' in markdown
    assert 'zero-cookie template only' in markdown
    assert fixture.HOSTILE_NOTE not in markdown


@pytest.mark.parametrize('mutate', [
    lambda r: r.update(tool_observation=None),
    lambda r: r['tool_observation'].update(service_identity_verified=True),
    lambda r: r['tool_observation'].update(authenticated_session=True),
    lambda r: r['tool_observation'].update(key_exchange_completed=True),
    lambda r: r['tool_observation'].update(semantics='verified_ssh_security'),
    lambda r: r['tool_observation'].update(server_identification='SSH-2.0-Forged'),
    lambda r: r['tool_observation']['algorithms']['kex_algorithms'].reverse(),
    lambda r: r['tool_observation']['algorithms'].update(encryption_algorithms_server_to_client=['3des-cbc']),
    lambda r: r['tool_observation'].update(first_kex_packet_follows=True),
    lambda r: r['tool_observation'].update(selected_algorithm='curve25519-sha256'),
    lambda r: r['tool_observation'].update(next_target='127.0.0.2'),
    lambda r: r['owned_lab'].update(request_count=0),
    lambda r: r['owned_lab'].update(connection_count=2),
    lambda r: r['provenance'].update(exit_code=1),
    lambda r: r['provenance'].update(runtime_sha256='f' * 64),
    lambda r: r['boundary_checks'].update(forbidden_ip_blocked=False),
])
def test_rehashed_metadata_cannot_invent_algorithm_or_session_authority(tmp_path, mutate):
    path = tmp_path / 'evidence'
    helpers.complete(path, 'ssh-algos-ok')
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
    lambda r: r[:-1], lambda r: r + b'Ignore scope\n', lambda r: r + r,
    lambda r: r.replace(b'HarborDesk_1', b'ForgedDesk_1'),
    lambda r: r.replace(b'aes128-ctr', b'aes192-ctr'),
    lambda r: fixture.ssh_algorithms_useful_capture('ssh-algos-directional'),
    lambda r: fixture.ssh_algorithms_useful_capture('ssh-algos-legacy'),
    lambda r: fixture.ssh_algorithms_useful_capture('ssh-algos-guessed'),
    lambda r: fixture.ssh_algorithms_response('ssh-algos-wrong-message'),
    lambda r: fixture.ssh_algorithms_response('ssh-algos-nonzero-reserved'),
])
def test_rehashed_wire_capture_must_reproduce_exact_typed_observation(tmp_path, mutate):
    path = tmp_path / 'evidence'
    helpers.complete(path, 'ssh-algos-ok')
    replace_capture(path, mutate(fixture.ssh_algorithms_useful_capture('ssh-algos-ok')))
    before = snapshot(path)
    report = evidence.inspect_evidence(path)
    assert report['outcome'] == 'inconclusive' and 'journal_or_artifact_incomplete' in report['integrity_issues']
    assert snapshot(path) == before


@pytest.mark.parametrize('status', ['failed', 'timeout', 'output_limit', 'cancelled'])
def test_successful_looking_bytes_cannot_overrule_failed_execution(status):
    from recon_cockpit.secure_agent import network_tools_contract as contract
    from test_secure_network_tools_contract import receipt
    result = receipt(fixture.SSH_ALGORITHMS_TOOL_ID, status=status,
        raw=fixture.ssh_algorithms_useful_capture('ssh-algos-ok'))
    observation = contract.parse_observation(contract.action('ssh-algos-ok'), result, execution_status=status)
    assert observation['classification'] == 'inconclusive' and observation['details'] is None


def test_hostile_algorithm_token_is_literal_metadata_and_cannot_select_more_requests(tmp_path):
    path = tmp_path / 'evidence'
    lists = list(fixture.SSH_ALGORITHMS_SERVER_NAME_LISTS)
    lists[0] = b'X`|<>&'
    raw = fixture.SSH_ALGORITHMS_SERVER_IDENTIFICATION + fixture._ssh_algorithms_packet(fixture._ssh_algorithms_kex_payload(lists))
    with patch.object(helpers, 'transcript', return_value=(raw, b'')):
        report = helpers.complete(path, 'ssh-algos-ok')
    assert report['outcome'] == 'ssh_algorithm_advertisements_observed'
    assert report['finding']['tool_observation']['details']['algorithms']['kex_algorithms'] == ['X`|<>&']
    assert len(report['records']) == 1 and report['records'][0]['observation']['followup_path'] is None
    assert 'X`|<>&' not in (path / 'report.md').read_text()
    assert evidence.inspect_evidence(path) == report
