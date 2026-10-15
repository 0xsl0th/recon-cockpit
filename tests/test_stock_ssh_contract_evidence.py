"""Evidence replay with portable protocol doubles, never native acceptance."""

import base64
from copy import deepcopy
import hashlib
import json
import os
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import stock_ssh_contract as contract, stock_ssh_evidence as evidence
from recon_cockpit.secure_agent import stock_ssh_spec as spec, stock_ssh_process as process
from recon_cockpit.secure_agent import stock_ssh_parser as parser, stock_ssh_parser_runtime as isolated
from recon_cockpit.secure_agent.stock_ssh_client_runtime import boundary_names, client_runtime_module
from recon_cockpit.secure_agent.stock_http_owner_worker import BOUNDS as RECORDER_BOUNDS
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.controller import Controller
from test_stock_ssh_client import envelope, SESSION
from test_stock_ssh_recorder import Harness
from test_stock_ssh_owner_worker import transport
from test_stock_ssh_process import complete_receipt
from test_stock_ssh_parser import xml, key, banner


def manifest(configuration="A", case="O2", approval=False):
    bound = envelope(configuration, case)
    return {"schema_version": "1", "assessment_id": str(uuid4()), "session_id": SESSION,
        "selection": bound["selection"], "policy": contract.policy_for_selection(bound["selection"], require_approval=approval).to_dict(),
        "limits": contract.limits(bound["selection"]), "runtime": bound["runtime"], "identity": bound["identity"]}


def owner_boundary(chosen):
    digest = chosen["identity"]["daemon_runtime_sha256"]
    names = lambda n: {key:key + ":[" + str(n) + "]" for key in ("user", "net", "mnt", "pid")}
    return {"custodian": {"ready": True, "namespaces": names(300), "namespace_identity": {
        "uid":65534, "gid":65534, "supplementary_groups":[65534], "setgroups_policy":"deny", "group_mutation_denied":True},
        "bounds":dict(process.BOUNDS), "runtime_digest":digest},
        "recorder":{"ready":True,"namespaces":names(200),"witness_baselines":True,"bounds":dict(RECORDER_BOUNDS),
                    "runtime_digest":digest,"private_transport":transport(chosen["selection"]["case"])},
        "launcher_mapping":{"uid_map":[[65534,1000,1]],"gid_map":[[65534,1000,1]],"launcher_uid":1000,"launcher_gid":1000}}


def rebind(result):
    owner = result["stock_ssh_owner"]
    result["owned_lab"].update(connection_count=owner["connection_count"],request_count=owner["request_count"],
        owner_receipt_sha256=hashlib.sha256(spec.encode(owner)).hexdigest())
    result["stock_ssh_closure"].update({name:deepcopy(owner[name]) for name in ("connection_count","request_count","recorder","instances")})


def peer_result(monkeypatch, chosen):
    configuration, case = chosen["selection"]["configuration"], chosen["selection"]["case"]
    harness = Harness(monkeypatch,configuration,case)
    try:
        if case in spec.NMAP_CASES or case in ("N3","N4"):
            client = harness.initial()
            if case == "N3":
                harness.clock=harness.service.action_deadline
                harness.step()
            elif case in spec.NMAP_CASES:
                client.close()
                harness.until(lambda:harness.service.active is None)
        elif case == "N6":
            client=harness.exchange_to_server_kex()
            client.close()
            harness.until(lambda:harness.service.active is None)
        else:
            harness.exchange_to_reply()
        harness.service.close()
        ledger=harness.service.snapshot()
    finally:
        harness.close()
    boundary = owner_boundary(chosen)
    instances=[]
    for index,row in enumerate(item for item in ledger["connections"] if item["daemon_connected"]):
        receipt=complete_receipt()
        receipt["descriptor"]=deepcopy(boundary["recorder"]["private_transport"]["pairs"][index])
        instances.append({"connection_id":row["id"],"receipt":receipt})
    owner={"connection_count":ledger["connections_admitted"],"request_count":ledger["server_key_replies_forwarded"],
           "recorder":ledger,"instances":instances,"owner":boundary}
    status = "output_limit" if case == "N4" else "failed" if case in ("N2","N3","N5","N6") else "succeeded"
    raw,stderr = (xml(configuration,service={"name":"ssh","method":"table","conf":"3"}) if case == "N1" else xml(configuration),b"") if case in spec.NMAP_CASES else (
        b"x"*8192 if case == "N4" else b"" if case in spec.NEGATIVE_CASES else key(configuration),
        b"" if case in spec.NEGATIVE_CASES else banner(configuration," "+spec.HOSTILE_ADDENDUM if case == "R1" else ""))
    tool=contract.action(chosen["selection"])["tool_id"]
    observation=None if status != "succeeded" else parser.parse_output(tool,raw,stderr,configuration=configuration)
    result={"status":status,"results":[],"bytes_received":len(raw)+len(stderr),"truncated":status=="output_limit",
        "boundary_checks":dict.fromkeys(boundary_names(chosen["selection"]),True),"timing":{
            "owner_startup_ms":30,"client_startup_ms":20,"action_elapsed_ms":2000 if case=="N3" else 90,"owner_teardown_ms":10},
        "tool_observation":observation,"backend":contract.BACKEND,"stock_ssh_owner":owner,
        "owned_lab":{"identity":chosen["identity"]},"stock_ssh_closure":{"identity":chosen["identity"],"status":"closed",
            "started":True,"processes_reaped":True,"namespace_descriptors_closed":True},
        "raw_output_base64":base64.b64encode(raw).decode(),"raw_stderr_base64":base64.b64encode(stderr).decode(),
        "provenance":{"runtime_sha256":client_runtime_module(chosen["selection"]).manifest_digest(chosen["runtime"]["client"]),
            "runtime_manifest":chosen["runtime"]["client"],"output_sha256":hashlib.sha256(raw).hexdigest(),
            "stderr_sha256":hashlib.sha256(stderr).hexdigest(),"parser_version":parser.parser_version(tool),
            "exit_code":0 if status=="succeeded" else 1,"stop_reason":status if status in ("timeout","output_limit") else None}}
    rebind(result)
    return result


@pytest.fixture(autouse=True)
def portable_parser(monkeypatch):
    monkeypatch.setattr(isolated,"parse_isolated_tool_output",lambda tool,raw,stderr,*,configuration,**kw:
                        parser.parse_output(tool,raw,stderr,configuration=configuration))


def save(directory, chosen, result, *, execute=True):
    policy=contract.validate_policy(chosen["policy"],chosen["selection"])
    class Backend:
        name=contract.BACKEND
        def check_available(self,action=None):pass
        def run(self,action,policy):return deepcopy(result)
    with evidence.StockSshEvidenceStore(directory,chosen) as store:
        with AuditSink(directory/"audit.jsonl") as audit:
            controller=Controller(policy,audit,Backend(),session_id=SESSION,evidence=store)
            outcome=controller.submit(contract.action(chosen["selection"]),execute=execute,session_step=1)
        return store.finalize(outcome,elapsed_ms=2100)


@pytest.mark.parametrize("configuration,case",spec.TRIALS)
def test_all_twenty_finite_cases_replay_original_bytes_transformations_and_usefulness(tmp_path,monkeypatch,configuration,case):
    chosen=manifest(configuration,case)
    result=peer_result(monkeypatch,chosen)
    report=save(tmp_path/"trial",chosen,result)
    assert report["case_passed"] and report["native_response_verified"]
    assert report["metrics"]["useful_completion"] == (case not in spec.NEGATIVE_CASES)
    assert report["metrics"]["expected_negative"] == (case in spec.NEGATIVE_CASES)
    before={p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in (tmp_path/"trial").iterdir()}
    assert evidence.inspect_trial(tmp_path/"trial")==report
    assert before=={p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in (tmp_path/"trial").iterdir()}


@pytest.mark.parametrize("fault",("fork_count","missing_exit","wrong_image","peer_cookie","peer_inode","peer_endpoint",
    "wrong_instance","duplicate_instance","open_listener","same_namespaces","uid_zero","host_root_mapping",
    "changed_bound","counter","bool_counter","owner_digest","unreaped","changed_closure"))
def test_recommitted_owner_receipts_cannot_forge_execution_transport_or_cleanup(monkeypatch,fault):
    chosen=manifest();result=peer_result(monkeypatch,chosen)
    owner=result["stock_ssh_owner"]; receipt=owner["instances"][0]["receipt"]
    if fault=="fork_count":receipt["fork_attempts"]=1
    elif fault=="missing_exit":receipt["events"].pop()
    elif fault=="wrong_image":receipt["events"][0]["image"]="/usr/bin/python3"
    elif fault=="peer_cookie":receipt["descriptor"]["netns_cookie"]+=1
    elif fault=="peer_inode":receipt["descriptor"]["inode"]+=1
    elif fault=="peer_endpoint":receipt["descriptor"]["peer"][0]="10.77.0.99"
    elif fault=="wrong_instance":owner["instances"][0]["connection_id"]+=1
    elif fault=="duplicate_instance":owner["instances"].append(deepcopy(owner["instances"][0]))
    elif fault=="open_listener":owner["owner"]["recorder"]["private_transport"]["private_listener_closed"]=False
    elif fault=="same_namespaces":owner["owner"]["recorder"]["namespaces"]=owner["owner"]["custodian"]["namespaces"]
    elif fault=="uid_zero":owner["owner"]["custodian"]["namespace_identity"]["uid"]=0
    elif fault=="host_root_mapping":owner["owner"]["launcher_mapping"]["launcher_uid"]=0
    elif fault=="changed_bound":owner["owner"]["custodian"]["bounds"]["max_internal_fork_attempts"]=3
    elif fault=="counter":owner["request_count"]=0
    elif fault=="bool_counter":owner["connection_count"]=True
    elif fault=="unreaped":receipt["all_server_processes_reaped"]=False
    rebind(result)
    if fault=="owner_digest":result["owned_lab"]["owner_receipt_sha256"]="f"*64
    elif fault=="changed_closure":result["stock_ssh_closure"]["namespace_descriptors_closed"]=False
    with pytest.raises(ValueError):evidence.validate_result(result,chosen)


@pytest.mark.parametrize("fault",("saved_observation","raw_output","runtime","output_hash","parser","false_boundary",
    "extra_boundary","timing_bool","timing_overflow","bytes","base64_noncanonical","base64_type"))
def test_saved_client_conclusions_cannot_override_raw_provenance(monkeypatch,fault):
    chosen=manifest();result=peer_result(monkeypatch,chosen)
    if fault=="saved_observation":result["tool_observation"]["trust"]="verified"
    elif fault=="raw_output":result["raw_output_base64"]=base64.b64encode(b"invented").decode()
    elif fault=="runtime":result["provenance"]["runtime_sha256"]="f"*64
    elif fault=="output_hash":result["provenance"]["output_sha256"]="f"*64
    elif fault=="parser":result["provenance"]["parser_version"]="accepted-http-parser"
    elif fault=="false_boundary":result["boundary_checks"][next(iter(result["boundary_checks"]))]=False
    elif fault=="extra_boundary":result["boundary_checks"]["claim"]=True
    elif fault=="timing_bool":result["timing"]["action_elapsed_ms"]=True
    elif fault=="timing_overflow":result["timing"]["action_elapsed_ms"]=60001
    elif fault=="bytes":result["bytes_received"]+=1
    elif fault=="base64_noncanonical":result["raw_output_base64"]="Zh=="
    else:result["raw_output_base64"]=b"Zg=="
    with pytest.raises(ValueError):evidence.validate_result(result,chosen)


@pytest.mark.parametrize("reason",("stock_ssh_fork_denied","stock_ssh_exec_denied","stock_ssh_custody_error","stock_ssh_instance_timeout"))
def test_key_output_followed_by_custody_violation_is_not_useful_acceptance(tmp_path,monkeypatch,reason):
    chosen=manifest();result=peer_result(monkeypatch,chosen)
    result["stock_ssh_owner"]["instances"][0]["receipt"]["stop_reason"]=reason
    rebind(result)
    report=save(tmp_path/"trial",chosen,result)
    assert not report["case_passed"] and not report["native_response_verified"] and not report["metrics"]["useful_completion"]


@pytest.mark.parametrize("approval,execute,status",((False,False,"dry_run"),(True,False,"dry_run"),(True,True,"blocked")))
def test_dry_runs_and_missing_required_approval_cannot_become_native_acceptance(tmp_path,approval,execute,status):
    chosen=manifest(approval=approval)
    report=save(tmp_path/"trial",chosen,None,execute=execute)
    assert report["execution_status"]==status and not report["case_passed"]
    assert evidence.inspect_trial(tmp_path/"trial")==report


@pytest.mark.parametrize("artifact",("manifest.json","intent.json","outcome.json","report.json","audit.jsonl"))
def test_private_artifact_replay_rejects_rebound_or_forged_history(tmp_path,monkeypatch,artifact):
    chosen=manifest();result=peer_result(monkeypatch,chosen)
    directory=tmp_path/"trial";save(directory,chosen,result)
    path=directory/artifact
    if artifact=="audit.jsonl":
        rows=path.read_bytes().splitlines();path.write_bytes(b"\n".join(rows[::-1])+b"\n")
    else:
        value=json.loads(path.read_bytes())
        if artifact=="manifest.json":value["identity"]["session_id"]=str(uuid4())
        elif artifact=="intent.json":value["backend"]="other"
        elif artifact=="outcome.json":value["outcome"]["approval_reference"]="a"*48
        else:value["metrics"]["actual_provider_calls"]=1
        path.write_bytes(spec.encode(value))
    with pytest.raises(ValueError):evidence.inspect_trial(directory)


def test_ssh_artifact_limits_are_separate_committed_and_do_not_enlarge_tool_output(monkeypatch):
    from recon_cockpit.secure_agent import stock_http_evidence, models
    assert evidence.MAX_BYTES == 1048576 and evidence.MAX_JSON_BYTES == 262144
    assert stock_http_evidence.MAX_JSON_BYTES == models.MAX_JSON_BYTES == 32768
    selected = contract.selection("A", "O2")
    assert contract.action(selected)["parameters"]["max_output_bytes"] == 8192
    monkeypatch.setitem(contract.EVIDENCE_BOUNDS, "max_json_bytes", 262143)
    assert contract.selection("A", "O2")["selection_sha256"] != selected["selection_sha256"]
    with pytest.raises(ValueError): contract.validate_selection(selected)


def test_artifact_json_accepts_exact_byte_limit_and_rejects_one_extra_byte():
    raw = b'{"value":"' + b"a" * (evidence.MAX_JSON_BYTES - 12) + b'"}'
    assert len(raw) == evidence.MAX_JSON_BYTES
    assert evidence._decode(raw)["value"] == "a" * (evidence.MAX_JSON_BYTES - 12)
    with pytest.raises(ValueError): evidence._decode(raw + b" ")


@pytest.mark.parametrize("raw", (b'', b'[]', b'{"a":1,"a":2}', b'{"n":{"a":1,"a":2}}',
    b'{"n":NaN}', b'{"n":Infinity}', b'{"n":-Infinity}', b'{"n":1e999}', b'{"n":"\xff"}',
    '{"n":1}', pytest.param(b'{"n":' + b'[' * 65 + b'0' + b']' * 65 + b'}', id="nested-depth")))
def test_artifact_json_rejects_ambiguous_nonfinite_and_unbounded_input(raw):
    with pytest.raises(ValueError): evidence._decode(raw)


def test_private_writer_reserves_exact_aggregate_and_json_limits_before_writing(tmp_path):
    with evidence.StockSshEvidenceStore(tmp_path / "trial", manifest()) as store:
        with pytest.raises(evidence.EvidenceUnavailable):
            store._write_new("result.json", b"x" * (evidence.MAX_JSON_BYTES + 1), evidence.MAX_BYTES)
        assert not (store.directory / "result.json").exists()
        for name in ("intent.json", "result.json", "outcome.json"):
            store._write_new(name, b"x" * evidence.MAX_JSON_BYTES, evidence.MAX_BYTES)
        _, used = evidence._directory_contents(store._fd)
        store._write_new("report.json", b"x" * (evidence.MAX_BYTES - used), evidence.MAX_BYTES)
        assert evidence._directory_contents(store._fd)[1] == evidence.MAX_BYTES
        with pytest.raises(evidence.EvidenceUnavailable):
            store._write_new("audit.jsonl", b"x", evidence.MAX_BYTES)
        assert not (store.directory / "audit.jsonl").exists()


@pytest.mark.parametrize("fault", ("extra", "symlink", "hardlink", "public", "executable", "aggregate"))
def test_directory_inspection_rejects_extra_links_modes_and_aggregate_overflow(tmp_path, fault):
    path = tmp_path / "report.json"
    path.write_bytes(b"{}"); path.chmod(0o600)
    if fault == "extra": (tmp_path / "extra.json").write_bytes(b"{}")
    elif fault == "symlink":
        path.unlink(); path.symlink_to(tmp_path / "missing")
    elif fault == "hardlink": os.link(path, tmp_path / "outcome.json")
    elif fault == "public": path.chmod(0o644)
    elif fault == "executable": path.chmod(0o700)
    else: path.write_bytes(b"x" * (evidence.MAX_BYTES + 1))
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError): evidence._directory_contents(descriptor)
    finally: os.close(descriptor)
