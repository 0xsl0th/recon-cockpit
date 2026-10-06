"""Composed evidence bindings and replay; portable parsers stand in for custody."""
import base64
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import nmap_evidence as evidence, service_web_contract as contract
from recon_cockpit.secure_agent import network_tools_contract,network_tools_parser,network_tools_parser_runtime
from recon_cockpit.secure_agent import web_tools_contract,web_tools_parser,web_tools_parser_runtime
from recon_cockpit.secure_agent import http_headers_parser_runtime
from recon_cockpit.secure_agent.http_headers_parser import parse_http_headers
from recon_cockpit.secure_agent.evidence import EvidenceUnavailable
from recon_cockpit.secure_agent.models import parse_policy,parse_action
from recon_cockpit.secure_agent.session import _observation
from recon_cockpit.secure_agent.service_web_evidence import validate_runtime_bindings
from recon_cockpit.secure_agent.service_web_lab_contract import identity
from test_secure_network_tools_evidence import manifest as network_manifest,transcript
from test_secure_web_tools_evidence import manifest as web_manifest
from test_secure_web_tools_parser import ffuf_output,ffuf_rows
from test_secure_http_headers_evidence import result as header_result
from test_secure_web_evidence import mutate_result


@pytest.fixture(autouse=True)
def portable_parsers(monkeypatch):
    monkeypatch.setattr(network_tools_parser_runtime,'parse_isolated_tool',
        lambda tool,raw,stderr=b'',**kw:network_tools_parser.parse_tool_output(tool,raw,stderr))
    monkeypatch.setattr(web_tools_parser_runtime,'parse_isolated_tool',
        lambda tool,raw,**kw:web_tools_parser.parse_tool_output(tool,raw))
    monkeypatch.setattr(http_headers_parser_runtime,'parse_isolated_headers',lambda raw,**kw:parse_http_headers(raw))


def policy():
    return parse_policy(json.loads(Path('examples/secure-agent-service-web-policy.json').read_text()))


def runtimes():
    return {'nmap_service_identify_v1':network_manifest('nmap_service_identify_v1'),
            'ffuf_content_discovery_v1':web_manifest('ffuf_content_discovery_v1')}


def bindings():
    return {tool:hashlib.sha256(contract.encode(value)).hexdigest() for tool,value in runtimes().items()}


def result(store,step):
    if step==3:
        value=header_result(store,2)
    else:
        tool=('nmap_service_identify_v1','ffuf_content_discovery_v1')[step-1]
        raw,stderr=transcript('nmap-service-http') if step==1 else (ffuf_output(ffuf_rows()),b'')
        selected=runtimes()[tool]
        selected_contract=network_tools_contract if step==1 else web_tools_contract
        normalized=(network_tools_parser.parse_tool_output(tool,raw,stderr) if step==1
                    else web_tools_parser.parse_tool_output(tool,raw))
        value={'status':'succeeded','results':[],'tool_observation':normalized,
            'bytes_received':len(raw)+len(stderr),'truncated':False,
            'raw_output_base64':base64.b64encode(raw).decode(),
            'raw_stderr_base64':base64.b64encode(stderr).decode(),
            'boundary_checks':dict.fromkeys(selected_contract.BOUNDARY_FIELDS,True),
            'provenance':{'runtime_sha256':bindings()[tool],'runtime_manifest':selected,
                'output_sha256':hashlib.sha256(raw).hexdigest(),'stderr_sha256':hashlib.sha256(stderr).hexdigest(),
                'parser_version':selected_contract.parser_version(tool),'exit_code':0,'stop_reason':None}}
    return {**value,'backend':contract.BACKEND,'owned_lab':{'identity':store._manifest['owned_lab'],
        'connection_count':(3,11,12)[step-1],'request_count':(1,9,10)[step-1]}}


def complete(path,case='vulnerable',*,with_commitment=True):
    pair=bindings() if with_commitment else None
    digest=hashlib.sha256(contract.encode(pair)).hexdigest() if pair else None
    with evidence.NmapEvidenceStore(path,session_id=str(uuid4()),policy=policy(),case=case,
            owned_lab=identity(case,str(uuid4())),workflow_profile='service_web',
            runtime_sha256=digest,runtime_bindings=pair) as store:
        frame=_observation(1,None)
        for step in (1,2,3):
            decision=store.record_decision(step,frame)
            assert decision.action==contract.action(case,step)
            value=result(store,step)
            execution=store.start(parse_action(decision.action),policy(),session_id=store._manifest['session_id'],
                                  session_step=step,backend=contract.BACKEND)
            store.finish(execution,value,execution_status='succeeded')
            frame=_observation(step+1,{'execution_status':'succeeded','untrusted_result':value})
        store.record_lab_closed({**store._lab_context,'status':'closed'})
        return store.finalize({'session_id':store._manifest['session_id'],'mode':'execute',
            'session_status':'completed','stop_reason':'coordinator_done','steps_attempted':3,
            'actions_succeeded':3,'output_reserved_bytes':18432})


@pytest.mark.parametrize('case,outcome',[('vulnerable','gaps_observed'),
    ('corrected','reviewed_headers_present'),('injected','gaps_observed')])
def test_complete_three_action_report_and_runtime_pair_replay_unchanged(tmp_path,case,outcome):
    path=tmp_path/'evidence';report=complete(path,case)
    assert report['outcome']==outcome and report['integrity_issues']==[]
    assert report['runtime_bindings']==bindings() and len(report['records'])==3
    assert report['owned_lab']['closure']['request_count']==10
    assert report['finding']['headers']['content_type']=='text/html'
    before={p.name:(p.read_bytes(),p.stat().st_mtime_ns,p.stat().st_mode) for p in path.iterdir()}
    assert evidence.inspect_evidence(path)==report
    assert before=={p.name:(p.read_bytes(),p.stat().st_mtime_ns,p.stat().st_mode) for p in path.iterdir()}
    assert '127.0.0.2' not in (path/'report.md').read_text()


@pytest.mark.parametrize('value,digest',[(None,'a'*64),({},'a'*64),([],None),
    ({'nmap_service_identify_v1':'a'*64},'b'*64),
    ({'nmap_service_identify_v1':True,'ffuf_content_discovery_v1':'b'*64},'c'*64),
    ({'nmap_service_identify_v1':'A'*64,'ffuf_content_discovery_v1':'b'*64},'c'*64)])
def test_runtime_pair_validation_cannot_drop_or_replace_one_binding(value,digest):
    with pytest.raises(ValueError):validate_runtime_bindings(value,digest)


def test_execution_without_committed_runtime_pair_cannot_publish_evidence(tmp_path):
    with pytest.raises(EvidenceUnavailable):complete(tmp_path/'evidence',with_commitment=False)
    assert not (tmp_path/'evidence/report.json').exists()


@pytest.mark.parametrize('step,change',[
    (1,lambda r:r['provenance'].update(runtime_sha256='c'*64)),
    (2,lambda r:r['provenance'].update(runtime_sha256='c'*64)),
    (1,lambda r:r.update(tool_observation=None)),
    (2,lambda r:r.update(tool_observation=None)),
    (3,lambda r:r['http_headers'].update(csp='present')),
    (1,lambda r:r['owned_lab'].update(request_count=0)),
    (2,lambda r:r['owned_lab'].update(request_count=8)),
    (3,lambda r:r['owned_lab'].update(request_count=9)),
    (1,lambda r:r['boundary_checks'].update(forbidden_ip_blocked=False)),
    (2,lambda r:r['boundary_checks'].update(forbidden_port_blocked=False)),
    (3,lambda r:r['boundary_checks'].update(process_creation_blocked=False)),
])
def test_rehashed_artifacts_cannot_forge_runtime_observations_continuity_or_enforcement(tmp_path,step,change):
    path=tmp_path/'evidence';complete(path);mutate_result(path,step,change)
    replay=evidence.inspect_evidence(path)
    assert replay['outcome']=='inconclusive' and replay['integrity_issues']
    assert replay['finding']['headers'] is None


@pytest.mark.parametrize('change',[
    lambda m:m.pop('runtime_bindings'),
    lambda m:m['runtime_bindings'].update(ffuf_content_discovery_v1='c'*64),
    lambda m:m.update(planning_origin='model_live'),
])
def test_manifest_substitution_fails_closed_before_interpretation(tmp_path,change):
    path=tmp_path/'evidence';complete(path)
    p=path/'manifest.json';value=json.loads(p.read_text());change(value);p.write_bytes(contract.encode(value))
    with pytest.raises(EvidenceUnavailable):evidence.inspect_evidence(path)


def test_removing_both_runtime_commitments_cannot_turn_executions_into_dry_run(tmp_path):
    path=tmp_path/'evidence';complete(path)
    p=path/'manifest.json';value=json.loads(p.read_text());value.update(runtime_bindings=None,runtime_sha256=None)
    p.write_bytes(contract.encode(value));replay=evidence.inspect_evidence(path)
    assert replay['outcome']=='inconclusive' and replay['integrity_issues']


@pytest.mark.parametrize('parser_module,method',[(network_tools_parser_runtime,'parse_isolated_tool'),
    (web_tools_parser_runtime,'parse_isolated_tool'),(http_headers_parser_runtime,'parse_isolated_headers')])
def test_parser_custody_failure_never_falls_back_to_host_parsing(tmp_path,monkeypatch,parser_module,method):
    from recon_cockpit.secure_agent.isolation import IsolationUnavailable
    def fail(*args,**kwargs):raise IsolationUnavailable('refused')
    monkeypatch.setattr(parser_module,method,fail)
    with pytest.raises(EvidenceUnavailable):complete(tmp_path/'evidence')
    assert not (tmp_path/'evidence/report.json').exists()
