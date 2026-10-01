"""Private HTTP wire evidence/replay; pure parsers stand in for Linux custody."""
import base64
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import http_headers_contract as contract
from recon_cockpit.secure_agent import http_headers_workflow as workflow
from recon_cockpit.secure_agent import http_headers_parser_runtime as parser_runtime
from recon_cockpit.secure_agent import nmap_evidence as evidence
from recon_cockpit.secure_agent.assessment_contract import _BOUNDARY_FIELDS
from recon_cockpit.secure_agent.evidence import EvidenceUnavailable
from recon_cockpit.secure_agent.http_headers_fixture import response, PORTAL_PATH, OPERATOR_NOTE
from recon_cockpit.secure_agent.http_headers_lab_contract import identity
from recon_cockpit.secure_agent.http_headers_parser import parse_http_headers
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.nmap_parser import parse_nmap_xml
from recon_cockpit.secure_agent.session import _observation
from test_secure_nmap_evidence import RUNTIME_DIGEST, result as nmap_result
from test_secure_web_evidence import mutate_result


@pytest.fixture(autouse=True)
def portable_parser_doubles(monkeypatch):
    monkeypatch.setattr(evidence.nmap_runtime, "parse_isolated_xml",
                        lambda raw, **kwargs: parse_nmap_xml(raw)["results"])
    monkeypatch.setattr(parser_runtime, "parse_isolated_headers", lambda raw, **kwargs: parse_http_headers(raw))


def policy():
    return parse_policy(json.loads(Path('examples/secure-agent-http-headers-policy.json').read_text()))


def wire(case):
    status, body, headers = response(case, PORTAL_PATH)
    return (b'HTTP/1.1 ' + str(status).encode() + b' OK\r\n' + headers
            + b'Content-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)


def result(store, step, raw=None):
    if step == 1:
        value = nmap_result(store, 1)
    else:
        raw = wire(store._manifest['fixture_case']) if raw is None else raw
        try:
            normalized = parse_http_headers(raw)
        except ValueError:
            normalized = None
        value = {'status': 'succeeded', 'bytes_received': len(raw), 'truncated': False,
                 'boundary_checks': dict.fromkeys(_BOUNDARY_FIELDS, True), 'http_headers': normalized,
                 'results': [{'target': '127.0.0.1', 'port': 8080, 'bytes_received': len(raw),
                              'truncated': False, 'raw_response': base64.b64encode(raw).decode('ascii'),
                              'response_sha256': hashlib.sha256(raw).hexdigest()}]}
    return {**value, 'backend': contract.BACKEND,
            'owned_lab': {'identity': store._manifest['owned_lab'], 'connection_count': step + 1,
                          'request_count': step - 1}}


def complete(path, case='vulnerable', *, raw=None):
    with evidence.NmapEvidenceStore(path, session_id=str(uuid4()), policy=policy(), case=case,
            owned_lab=identity(case, str(uuid4())), runtime_sha256=RUNTIME_DIGEST,
            workflow_profile='http_headers') as store:
        frame = _observation(1, None)
        for step in (1, 2):
            decision = store.record_decision(step, frame)
            assert decision.action == contract.action(case, step)
            assert decision.done is (step == 2)
            value = result(store, step, raw)
            execution = store.start(parse_action(decision.action), policy(), session_id=store._manifest['session_id'],
                                    session_step=step, backend=contract.BACKEND)
            store.finish(execution, value, execution_status='succeeded')
            frame = _observation(step + 1, {'execution_status': 'succeeded', 'untrusted_result': value})
        store.record_lab_closed({**store._lab_context, 'status': 'closed'})
        return store.finalize({'session_id': store._manifest['session_id'], 'mode': 'execute',
            'session_status': 'completed', 'stop_reason': 'coordinator_done', 'steps_attempted': 2,
            'actions_succeeded': 2, 'output_reserved_bytes': 18432})


@pytest.mark.parametrize('case,outcome', [('vulnerable', 'gaps_observed'),
    ('corrected', 'reviewed_headers_present'), ('injected', 'gaps_observed')])
def test_completed_two_action_evidence_replays_readonly_and_keeps_raw_text_private(tmp_path, case, outcome):
    path = tmp_path / 'evidence'
    report = complete(path, case)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}
    assert report['outcome'] == outcome and report['integrity_issues'] == []
    assert report['workflow_card'] == workflow.card_identity()
    assert report['summary']['actions_succeeded'] == 2
    assert report['owned_lab']['closure']['request_count'] == 1
    assert report['live_calls_enabled'] is False
    assert report['finding']['headers']['content_type'] == 'text/html'
    assert evidence.inspect_evidence(path) == report
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}
    assert all(p.stat().st_mode & 0o077 == 0 for p in path.iterdir())
    if case == 'injected':
        artifact = json.loads((path / report['records'][1]['artifact']['filename']).read_bytes())
        assert OPERATOR_NOTE.encode() in base64.b64decode(artifact['results'][0]['raw_response'])
        for filename in ('report.json', 'report.md', 'evidence.jsonl'):
            assert OPERATOR_NOTE not in (path / filename).read_text()
            assert '127.0.0.2' not in (path / filename).read_text()


@pytest.mark.parametrize('change', [
    lambda r: r['results'][0].update(response_sha256='a' * 64),
    lambda r: r['http_headers'].update(csp='present'),
    lambda r: r.update(http_headers=None),
    lambda r: r['results'][0].update(raw_response=base64.b64encode(b'HTTP/1.1 200 OK\r\n\r\n').decode()),
    lambda r: r['boundary_checks'].update(forbidden_ip_blocked=False),
    lambda r: r['owned_lab'].update(request_count=2),
])
def test_rehashed_artifacts_cannot_relabel_wire_header_evidence(tmp_path, change):
    path = tmp_path / 'evidence'
    complete(path)
    mutate_result(path, 2, change)
    report = evidence.inspect_evidence(path)
    assert report['outcome'] == 'inconclusive'
    assert 'journal_or_artifact_incomplete' in report['integrity_issues']
    assert report['finding']['headers'] is None


@pytest.mark.parametrize('raw', [b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nshort',
    b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n',
    b'HTTP/1.1 302 Found\r\nLocation: http://127.0.0.2:8080/\r\nContent-Length: 0\r\n\r\n'])
def test_unsupported_or_redirect_response_remains_inconclusive_with_replay(tmp_path, raw):
    path = tmp_path / 'evidence'
    report = complete(path, raw=raw)
    assert report['outcome'] == 'inconclusive'
    assert evidence.inspect_evidence(path) == report


def test_parser_failure_does_not_publish_findings(tmp_path, monkeypatch):
    from recon_cockpit.secure_agent.isolation import IsolationUnavailable
    monkeypatch.setattr(parser_runtime, 'parse_isolated_headers',
                        lambda *a, **k: (_ for _ in ()).throw(IsolationUnavailable('unavailable')))
    path = tmp_path / 'evidence'
    with pytest.raises(EvidenceUnavailable):
        complete(path)
    assert not (path / 'report.json').exists()


def test_header_evidence_cannot_enable_model_planning(tmp_path):
    path = tmp_path / 'evidence'
    complete(path)
    manifest = json.loads((path / 'manifest.json').read_bytes())
    manifest['planning_origin'] = 'model_live'
    (path / 'manifest.json').write_bytes(contract.encode(manifest))
    with pytest.raises(EvidenceUnavailable):
        evidence.inspect_evidence(path)
