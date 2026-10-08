"""Native captures and independent owner framing must agree on read-only replay."""
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_nuclei_fixture as fixture
from recon_cockpit.secure_agent import network_tools_nuclei_runtime as runtime
from recon_cockpit.secure_agent import network_tools_parser as parser
from recon_cockpit.secure_agent import network_tools_parser_runtime as parser_runtime
from recon_cockpit.secure_agent import nmap_evidence as evidence
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.network_tools_lab_contract import identity
from recon_cockpit.secure_agent.network_tools_runtime import manifest_digest
from recon_cockpit.secure_agent.session import _observation
from test_secure_nuclei_parser import CAPTURED_MATCHED, CAPTURED_UNMATCHED
from test_secure_web_evidence import mutate_result


@pytest.fixture(autouse=True)
def portable_parser_double(monkeypatch):
    monkeypatch.setattr(parser_runtime, 'parse_isolated_tool',
        lambda tool, raw, stderr=b'', **kw: parser.parse_tool_output(tool, raw, stderr,
            owner_response=kw.get('owner_response')))


def complete(path, matched=True):
    case = 'nuclei-index' if matched else 'nuclei-no-index'
    raw = CAPTURED_MATCHED if matched else CAPTURED_UNMATCHED
    wire = fixture.response(case)
    policy = parse_policy(json.loads(Path('examples/secure-agent-nuclei-policy.json').read_text()))
    action = parse_action(contract.action(case))
    manifest = runtime.manifest()
    digest = manifest_digest(manifest)
    with evidence.NmapEvidenceStore(path, session_id=str(uuid4()), policy=policy, case=case,
            owned_lab=identity(case, str(uuid4())), workflow_profile='network_tools', runtime_sha256=digest) as store:
        store.record_decision(1, _observation(1, None))
        execution = store.start(action, policy, session_id=store._manifest['session_id'], session_step=1, backend=contract.BACKEND)
        counts = {'identity': store._manifest['owned_lab'], 'connection_count': 1, 'request_count': 1}
        receipt = {'version': '1', 'bytes_sent': len(wire), 'response_base64': base64.b64encode(wire).decode(),
            'response_sha256': hashlib.sha256(wire).hexdigest(), 'send_complete': True, 'connection_closed': True}
        value = {'status': 'succeeded', 'results': [], 'tool_observation': parser.parse_tool_output(runtime.TOOL_ID, raw, owner_response=wire),
            'bytes_received': len(raw), 'truncated': False, 'raw_output_base64': base64.b64encode(raw).decode(),
            'raw_stderr_base64': '', 'boundary_checks': dict.fromkeys(contract.BOUNDARY_FIELDS | runtime.BOUNDARY_FIELDS, True),
            'backend': contract.BACKEND, 'owned_lab': {**counts, 'owner_response': receipt},
            'provenance': {'runtime_sha256': digest, 'runtime_manifest': manifest,
                'output_sha256': hashlib.sha256(raw).hexdigest(), 'stderr_sha256': hashlib.sha256(b'').hexdigest(),
                'parser_version': contract.parser_version(runtime.TOOL_ID), 'exit_code': 0, 'stop_reason': None}}
        store.finish(execution, value, execution_status='succeeded')
        store.record_lab_closed({**counts, 'status': 'closed'})
        return store.finalize({'session_id': store._manifest['session_id'], 'mode': 'execute', 'session_status': 'completed',
            'stop_reason': 'coordinator_done', 'steps_attempted': 1, 'actions_succeeded': 1, 'output_reserved_bytes': 8192})


def snapshot(path):
    return {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in path.iterdir()}


@pytest.mark.parametrize('matched', [True, False])
def test_both_useful_native_outcomes_replay_without_reexecution(tmp_path, matched):
    path = tmp_path / 'evidence'
    report = complete(path, matched)
    assert report['outcome'] == ('signature_present' if matched else 'signature_absent')
    before = snapshot(path)
    assert evidence.inspect_evidence(path) == report and snapshot(path) == before
    text = (path / 'report.md').read_text()
    assert 'does not verify exploitability' in text and 'Nuclei normalizes' in text


@pytest.mark.parametrize('fault', ['missing_owner', 'unfinished', 'unclosed', 'owner_hash', 'owner_body', 'owner_encoding',
    'owner_bytes', 'extra_request', 'no_request', 'tool_hash', 'matcher', 'predicate', 'schema', 'native_body',
    'scratch_boundary', 'exit_code', 'output_truncated'])
def test_rehashed_artifact_cannot_invent_useful_completion_or_hide_owner_framing(tmp_path, fault):
    path = tmp_path / 'evidence'
    complete(path)
    def mutate(value):
        receipt = value['owned_lab']['owner_response']
        if fault == 'missing_owner': del value['owned_lab']['owner_response']
        elif fault == 'unfinished': receipt['send_complete'] = False
        elif fault == 'unclosed': receipt['connection_closed'] = False
        elif fault == 'owner_hash': receipt['response_sha256'] = 'a' * 64
        elif fault in ('owner_body', 'owner_encoding'):
            wire = base64.b64decode(receipt['response_base64'])
            wire = (wire.replace(b'readme.txt', b'otherx.txt') if fault == 'owner_body' else
                wire.replace(b'Connection: close\r\n', b'Connection: close\r\nContent-Encoding: gzip\r\n'))
            receipt.update(response_base64=base64.b64encode(wire).decode(), bytes_sent=len(wire), response_sha256=hashlib.sha256(wire).hexdigest())
            value['tool_observation']['owner_response_sha256'] = receipt['response_sha256']
        elif fault == 'owner_bytes': receipt['bytes_sent'] += 1
        elif fault == 'extra_request': value['owned_lab']['request_count'] = 2
        elif fault == 'no_request': value['owned_lab']['request_count'] = 0
        elif fault == 'tool_hash': value['provenance']['runtime_sha256'] = 'a' * 64
        elif fault == 'matcher': value['tool_observation'].update(matcher_status=False, outcome='signature_absent')
        elif fault == 'predicate': value['tool_observation']['vulnerability_verified'] = True
        elif fault == 'schema': value['tool_observation']['followup'] = '127.0.0.2'
        elif fault == 'native_body':
            raw = base64.b64decode(value['raw_output_base64']).replace(b'readme.txt', b'otherx.txt')
            value.update(raw_output_base64=base64.b64encode(raw).decode(), bytes_received=len(raw))
            value['provenance']['output_sha256'] = hashlib.sha256(raw).hexdigest()
        elif fault == 'scratch_boundary': value['boundary_checks']['scratch_noexec'] = False
        elif fault == 'exit_code': value['provenance']['exit_code'] = 1
        else: value['truncated'] = True
    mutate_result(path, 1, mutate)
    before = snapshot(path)
    report = evidence.inspect_evidence(path)
    assert report['outcome'] == 'inconclusive' and report['finding']['tool_observation'] is None
    assert 'journal_or_artifact_incomplete' in report['integrity_issues']
    assert snapshot(path) == before


@pytest.mark.parametrize('owner', [None, b'', 'HTTP', b'x' * 4097])
def test_isolated_parser_requires_bounded_original_response_before_launch(monkeypatch, owner):
    monkeypatch.setattr(parser_runtime, '_runtime_files', lambda *a, **k: pytest.fail('parser launched'))
    with pytest.raises(ValueError):
        parser_runtime.parse_isolated_tool_output(runtime.TOOL_ID, CAPTURED_MATCHED, owner_response=owner)


def test_old_parser_transport_payload_stays_identical_and_nuclei_frame_is_separate(monkeypatch):
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.isolation import IsolationUnavailable
    import time
    payloads = []
    monkeypatch.setattr(parser_runtime, '_command', lambda *_: ['parser'])
    monkeypatch.setattr(parser_runtime, '_capture_bounded', lambda argv, raw, *a, **k: (payloads.append(raw) or (78, b'', b'', None)))
    control = ExecutionControl(time.monotonic() + 10)
    for tool, owner in [('dig_dns_query_v1', None), (runtime.TOOL_ID, b'owner')]:
        with pytest.raises(IsolationUnavailable):
            parser_runtime._parse_isolated(tool, b'out', b'err', control, (), owner)
    assert payloads == [b'\0\0\0\3outerr', b'\0\0\0\3\0\0\0\3outerrowner']
