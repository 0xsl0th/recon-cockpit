import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_workflow as workflow
from recon_cockpit.secure_agent import network_tools_tls_posture_parser as parser
from recon_cockpit.secure_agent import network_tools_tls_posture_parser_runtime as parser_runtime
from recon_cockpit.secure_agent import network_tools_tls_posture_runtime as runtime
from recon_cockpit.secure_agent import nmap_evidence as evidence
from recon_cockpit.secure_agent.network_tools_tls_posture_receipt import encode_owner_receipt
from recon_cockpit.secure_agent.network_tools_tls_posture_spec import TOOL_VERSIONS, VERSION_TO_TOOL, BOUNDARY_FIELDS
from recon_cockpit.secure_agent.network_tools_lab_contract import identity
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session import _observation
from test_network_tools_tls_posture_parser import sample
from test_tls_posture_observation_contract import observation_trial


@pytest.fixture(autouse=True)
def portable_worker(monkeypatch):
    def parse(tool, out, err, **extra):
        extra.pop("deadline", None); extra.pop("control", None)
        return parser.parse_input(parser.encode_input(tool, out, err, **extra))
    monkeypatch.setattr(parser_runtime, "parse_isolated_tls_posture", parse)


def receipt(version="tls1_3", *, rejection=False, hrr=False, owner_size=None):
    tool, out, err, extra = sample(version, rejection=rejection, hrr=hrr)
    if owner_size is not None:
        extra["owner_raw"] += b" " * (owner_size - len(extra["owner_raw"]))
    trial = observation_trial(version, rejection=rejection, hrr=hrr)
    manifest = {**trial["runtime_manifest"], "profile": runtime.PROFILE, "tool_id": tool}
    normalized = parser.parse_input(parser.encode_input(tool, out, err, **extra))
    return tool, {"status": "succeeded" if extra["exit_code"] == 0 else "failed", "results": [],
        "tool_observation": normalized, "tls_posture_owner": encode_owner_receipt(extra["owner_raw"]),
        "bytes_received": len(out) + len(err), "truncated": False,
        "raw_output_base64": base64.b64encode(out).decode(), "raw_stderr_base64": base64.b64encode(err).decode(),
        "boundary_checks": dict.fromkeys(contract.BOUNDARY_FIELDS | BOUNDARY_FIELDS, True),
        "provenance": {"runtime_sha256": runtime.manifest_digest(manifest), "runtime_manifest": manifest,
            "output_sha256": hashlib.sha256(out).hexdigest(), "stderr_sha256": hashlib.sha256(err).hexdigest(),
            "parser_version": parser.PARSER_VERSION, "exit_code": extra["exit_code"], "stop_reason": None}}


def complete(path, version="tls1_3", *, rejection=False, hrr=False, owner_size=None):
    tool, value = receipt(version, rejection=rejection, hrr=hrr, owner_size=owner_size)
    variant = value["tool_observation"]["fixture_variant"]
    case = f"tls-posture-{version}-{variant}"
    policy = parse_policy({"schema_version":"1", "policy_version":"tls-test", "allowed_targets":["127.0.0.1/32"],
        "allowed_tools":list(TOOL_VERSIONS), "allowed_ports":[8080], "allowed_methods":[], "max_timeout_seconds":5,
        "max_output_bytes":8192, "max_targets":1, "require_approval":True, "approval_ttl_seconds":60})
    with evidence.NmapEvidenceStore(path, session_id=str(uuid4()), policy=policy, case=case,
            owned_lab=identity(case,str(uuid4())), workflow_profile="network_tools",
            runtime_sha256=value["provenance"]["runtime_sha256"]) as store:
        store.record_decision(1, _observation(1,None))
        execution = store.start(parse_action(contract.action(case)), policy,
            session_id=store._manifest["session_id"], session_step=1, backend=contract.BACKEND)
        counts = {"identity":store._manifest["owned_lab"], "connection_count":1, "request_count":1}
        value.update(backend=contract.BACKEND, owned_lab={**counts,"tls_posture_owner_sha256":value["tls_posture_owner"]["sha256"]})
        store.finish(execution, value, execution_status=value["status"])
        store.record_lab_closed({**counts,"status":"closed"})
        failed = value["status"] == "failed"
        return store.finalize({"session_id":store._manifest["session_id"], "mode":"execute",
            "session_status":"stopped" if failed else "completed", "stop_reason":"action_failed" if failed else "coordinator_done",
            "steps_attempted":1, "actions_succeeded":0 if failed else 1, "output_reserved_bytes":8192})


@pytest.mark.parametrize("version", TOOL_VERSIONS.values())
@pytest.mark.parametrize("rejection", [False, True])
def test_failed_rejection_remains_failed_but_useful_replay_completes(tmp_path,version,rejection):
    path=tmp_path/'evidence';report=complete(path,version,rejection=rejection)
    assert report['outcome']=='tls_posture_'+('explicit_protocol_rejection' if rejection else 'handshake_completed')
    assert report['summary']['actions_succeeded']==int(not rejection)
    assert report['metrics']['legitimate_task_completed'] is True
    assert report['metrics']['useful_actions_completed']==1
    assert not report['metrics']['tested_unauthorized_actions_blocked']
    before={p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in path.iterdir()}
    assert evidence.inspect_evidence(path)==report
    assert before=={p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in path.iterdir()}
    result=json.loads(next(path.glob('result-*.json')).read_bytes())
    assert set(result['tls_posture_owner'])=={'filename','bytes','sha256','representation'}
    assert len(list(path.glob('tls-owner-*.json')))==1
    assert next(path.glob('result-*.json')).stat().st_size <= 65536


def test_hrr_does_not_inflate_legitimate_completion(tmp_path):
    report=complete(tmp_path/'evidence',hrr=True)
    assert report['outcome']=='tls_posture_extra_client_hello_prevented'
    assert report['metrics']['legitimate_task_completed'] is False
    assert report['metrics']['useful_actions_completed']==0
    assert report['metrics']['tested_unauthorized_actions_blocked']==1
    assert report['summary']['session_status']=='stopped'


@pytest.mark.parametrize('change',['delete','tamper','symlink','oversize','orphan'])
def test_owner_artifact_tampering_or_orphans_make_replay_inconclusive(tmp_path,change):
    path=tmp_path/'evidence';complete(path,rejection=True)
    owner=next(path.glob('tls-owner-*.json'))
    if change=='delete':owner.unlink()
    if change=='tamper':owner.write_bytes(owner.read_bytes()+b' ')
    if change=='symlink':
        other=tmp_path/'other.json';other.write_bytes(owner.read_bytes());owner.unlink();owner.symlink_to(other)
    if change=='oversize':owner.write_bytes(b' '*262145)
    if change=='orphan':
        other=path/'tls-owner-orphan.json';other.write_bytes(b'{}');other.chmod(0o600)
    report=evidence.inspect_evidence(path)
    assert report['outcome']=='inconclusive' and report['integrity_issues']
    assert not report['metrics']['legitimate_task_completed']


@pytest.mark.parametrize('field,value',[('exit_code',0),('stop_reason','timeout')])
def test_failed_usefulness_requires_exact_execution_fields(field,value):
    tool,result=receipt(rejection=True);result['provenance'][field]=value
    with pytest.raises(ValueError):contract.validate_tool_result(result,tool_id=tool,execution_status='failed')


def test_extra_boundary_witness_and_original_owner_are_mandatory():
    tool,result=receipt()
    for key in BOUNDARY_FIELDS:
        altered=deepcopy(result);altered['boundary_checks'].pop(key)
        with pytest.raises(ValueError):contract.validate_tool_result(altered,tool_id=tool,execution_status='succeeded')
    result.pop('tls_posture_owner')
    with pytest.raises(ValueError):contract.validate_tool_result(result,tool_id=tool,execution_status='succeeded')


def test_old_failed_tools_cannot_use_tls_exception():
    from test_secure_network_tools_contract import receipt as old_receipt
    result=old_receipt();result['status']='failed';result['provenance']['exit_code']=1
    with pytest.raises(ValueError):contract.validate_tool_result(result,tool_id=contract.DIG_TOOL_ID,execution_status='failed')


@pytest.mark.parametrize("source,claimed", [("hrr","modern"), ("hrr","legacy"), ("reject","legacy")])
def test_coherent_receipt_cannot_move_between_fixture_variants(source,claimed):
    tool,value=receipt(rejection=source=="reject", hrr=source=="hrr")
    selected=identity("tls-posture-tls1_3-"+claimed,str(uuid4()))
    value.update(backend=contract.BACKEND,owned_lab={"identity":selected,"connection_count":1,
        "request_count":1,"tls_posture_owner_sha256":value["tls_posture_owner"]["sha256"]})
    with pytest.raises(ValueError,match="tls_posture_owner_(?:progress|selection)_mismatch"):
        contract.validate_result_context(value,selected,tool_id=tool,execution_status="failed")


@pytest.mark.parametrize("stop_reason", ["cancelled", "session_timeout", "output_limit"])
def test_useful_receipt_cannot_override_session_stop_reason(stop_reason):
    tool,value=receipt(rejection=True)
    case="tls-posture-tls1_3-reject";action=parse_action(contract.action(case))
    row={"session_step":1,"execution_id":str(uuid4()),"observation_id":str(uuid4()),
        "action_digest":action.digest,"action":{k:v for k,v in action.to_dict().items() if k!="rationale"},
        "execution_status":"failed","observation":contract.classify_tool(tool,value["tool_observation"])}
    summary={"steps_attempted":1,"mode":"execute","session_status":"stopped","stop_reason":stop_reason}
    assert workflow.terminal_decision(case,[row],summary).reason=="session_stopped"


def test_maximum_owner_stays_separate_without_raising_existing_artifact_cap(tmp_path):
    path=tmp_path/'evidence';report=complete(path,rejection=True,owner_size=262144)
    assert next(path.glob('tls-owner-*.json')).stat().st_size == 262144
    assert next(path.glob('result-*.json')).stat().st_size < evidence.MAX_ARTIFACT_BYTES == 65536
    assert evidence.inspect_evidence(path) == report


def test_both_inspection_entrypoints_replay_same_receipt_without_writes(tmp_path,capsys):
    from recon_cockpit.secure_agent import cli, assessment_inspection
    path=tmp_path/'evidence';report=complete(path,rejection=True)
    before={p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in path.iterdir()}
    assert cli.main(['--inspect-assessment',str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == report
    assert assessment_inspection.inspect_saved_assessment(path) == report
    assert before == {p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in path.iterdir()}


@pytest.mark.parametrize("bad_field", ["case", "version", "counters"])
def test_inconclusive_owner_envelope_binding_is_checked_too(bad_field):
    tool,value=receipt(rejection=True);value['tool_observation']=None
    raw=json.loads(base64.b64decode(value['tls_posture_owner']['raw_base64']))
    if bad_field=='case':raw['diagnostic']['case']='legacy'
    if bad_field=='version':raw['diagnostic']['expected_version']='tls1'
    if bad_field=='counters':raw['request_count']=0
    owner=encode_owner_receipt(json.dumps(raw).encode());value['tls_posture_owner']=owner
    selected=identity('tls-posture-tls1_3-reject',str(uuid4()))
    value.update(backend=contract.BACKEND,owned_lab={'identity':selected,'connection_count':1,'request_count':1,
        'tls_posture_owner_sha256':owner['sha256']})
    with pytest.raises(ValueError):contract.validate_result_context(value,selected,tool_id=tool,execution_status='failed')
