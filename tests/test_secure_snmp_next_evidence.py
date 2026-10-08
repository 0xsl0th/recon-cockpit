"""Retained SNMP successor metadata never grants walk or target authority."""
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
from test_secure_snmp_next_parser import output


@pytest.fixture(autouse=True)
def portable_parser_double(monkeypatch):
    monkeypatch.setattr(parser_runtime, 'parse_isolated_tool',
        lambda tool, raw, stderr=b'', **kw: parser.parse_tool_output(tool, raw, stderr))


def snapshot(path):
    return {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in path.iterdir()}


@pytest.mark.parametrize('case', fixture.SNMP_NEXT_SUCCESS_CASES)
def test_successor_boundary_or_empty_description_replays_without_followup(tmp_path, case):
    path = tmp_path / 'evidence'
    report = helpers.complete(path, case)
    assert report['outcome'] == 'snmp_interface_next_observed' and report['integrity_issues'] == []
    observation = report['finding']['tool_observation']
    assert observation['followup_path'] is None
    details = observation['details']
    assert details['semantics'] == 'untrusted_snmp_successor_metadata'
    assert details['service_identity_verified'] is False
    assert details['query_oid'] == fixture.SNMP_NEXT_SEED_OID
    if case == 'snmp-next-empty':
        assert details['description'] == '' and details['interface_index'] == 1
    if case == 'snmp-next-end-of-view':
        assert details['outcome'] == 'end_of_mib_view' and details['description'] is None
    if case == 'snmp-next-outside-subtree':
        assert details['outcome'] == 'outside_ifdescr_subtree' and details['interface_index'] is None
    before = snapshot(path)
    assert evidence.inspect_evidence(path) == report and snapshot(path) == before
    markdown = (path / 'report.md').read_text()
    assert 'No returned OID was followed' in markdown
    assert 'does not establish real-model injection resistance' in markdown
    assert 'later wire bytes' in markdown


@pytest.mark.parametrize('mutate', [
    lambda r: r.update(tool_observation=None),
    lambda r: r['tool_observation'].update(service_identity_verified=True),
    lambda r: r['tool_observation'].update(semantics='verified_snmp_inventory'),
    lambda r: r['tool_observation'].update(query_oid='.1.3.6.1'),
    lambda r: r['tool_observation'].update(returned_oid=fixture.SNMP_NEXT_SEED_OID),
    lambda r: r['tool_observation'].update(interface_index=2),
    lambda r: r['tool_observation'].update(description='forged'),
    lambda r: r['tool_observation'].update(outcome='end_of_mib_view'),
    lambda r: r['tool_observation'].update(next_oid='.1.3.6.1.4.1'),
    lambda r: r['tool_observation'].update(next_target='127.0.0.2'),
    lambda r: r['owned_lab'].update(request_count=0),
    lambda r: r['owned_lab'].update(connection_count=2),
    lambda r: r['provenance'].update(exit_code=1),
    lambda r: r['provenance'].update(runtime_sha256='f' * 64),
    lambda r: r['boundary_checks'].update(forbidden_ip_blocked=False),
])
def test_rehashed_metadata_cannot_invent_successor_or_authority(tmp_path, mutate):
    path = tmp_path / 'evidence'
    helpers.complete(path, 'snmp-next-ok')
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
    lambda r: r.replace((fixture.SNMP_NEXT_SEED_OID + '.1').encode(), fixture.SNMP_NEXT_SEED_OID.encode()),
    lambda r: r.replace((fixture.SNMP_NEXT_SEED_OID + '.1').encode(), (fixture.SNMP_NEXT_SEED_OID + '.2').encode()),
    lambda r: output('snmp-next-empty'), lambda r: output('snmp-next-end-of-view'),
    lambda r: output('snmp-next-outside-subtree'), lambda r: r.replace(b'Hex-STRING', b'STRING'),
])
def test_rehashed_capture_must_reproduce_exact_typed_observation(tmp_path, mutate):
    path = tmp_path / 'evidence'
    helpers.complete(path, 'snmp-next-ok')
    replace_capture(path, mutate(output()))
    before = snapshot(path)
    report = evidence.inspect_evidence(path)
    assert report['outcome'] == 'inconclusive' and 'journal_or_artifact_incomplete' in report['integrity_issues']
    assert snapshot(path) == before


@pytest.mark.parametrize('status', ['failed', 'timeout', 'output_limit', 'cancelled'])
def test_successful_looking_bytes_cannot_overrule_failed_execution(status):
    from recon_cockpit.secure_agent import network_tools_contract as contract
    from test_secure_network_tools_contract import receipt
    result = receipt(fixture.SNMP_NEXT_TOOL_ID, status=status, raw=output())
    observation = contract.parse_observation(contract.action('snmp-next-ok'), result, execution_status=status)
    assert observation['classification'] == 'inconclusive' and observation['details'] is None


def test_hostile_description_is_literal_metadata_and_cannot_select_more_requests(tmp_path):
    path = tmp_path / 'evidence'
    raw = (fixture.SNMP_NEXT_SEED_OID + '.1 = Hex-STRING: 58 60 7C 2A \n').encode()
    with patch.object(helpers, 'transcript', return_value=(raw, b'')):
        report = helpers.complete(path, 'snmp-next-ok')
    assert report['outcome'] == 'snmp_interface_next_observed'
    assert report['finding']['tool_observation']['details']['description'] == 'X`|*'
    assert len(report['records']) == 1 and report['records'][0]['observation']['followup_path'] is None
    assert 'X`|*' not in (path / 'report.md').read_text()
    assert evidence.inspect_evidence(path) == report
