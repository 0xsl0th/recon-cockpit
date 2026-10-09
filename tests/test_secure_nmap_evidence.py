"""Offline fixtures exercise durable Nmap evidence and adversarial replay."""

import base64
import copy
import hashlib
import json
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import nmap_contract as contract, nmap_evidence as evidence
from recon_cockpit.secure_agent import nmap_workflow as workflow
from recon_cockpit.secure_agent.evidence import EvidenceUnavailable
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.nmap_parser import PARSER_VERSION, parse_nmap_xml
from recon_cockpit.secure_agent.owned_lab_contract import identity
from recon_cockpit.secure_agent.session import _observation
from recon_cockpit.secure_agent.worker import _response


XML = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun><nmaprun scanner="nmap"><scaninfo type="connect" protocol="tcp"
numservices="1" services="8080"/><host><status state="up"/>
<address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="8080">
<state state="open"/></port></ports></host><runstats><finished exit="success"/>
<hosts up="1" down="0" total="1"/></runstats></nmaprun>'''
RUNTIME_MANIFEST = {
    "version": "1", "profile": "nmap-tcp-connect-runtime-v1", "executable": "/tool/nmap",
    "interpreter": "/lib64/ld-linux-x86-64.so.2", "files": [
        {"source": source, "destination": destination, "size": 4,
         "sha256": hashlib.sha256(b"data").hexdigest()}
        for source, destination in sorted([
            ("/usr/lib/nmap/nmap", "/tool/nmap"),
            ("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2"),
            ("/usr/share/nmap/nmap-services", "/tool/data/nmap-services"),
            ("/usr/share/nmap/nmap-protocols", "/tool/data/nmap-protocols"),
        ], key=lambda row: row[1])
    ],
}
RUNTIME_DIGEST = hashlib.sha256(contract.encode(RUNTIME_MANIFEST)).hexdigest()


@pytest.fixture(autouse=True)
def unit_only_parser_double(monkeypatch):
    # Portable data-contract tests only. Linux integration runs the actual
    # no-network/no-exec parser sandbox for both capture and read-only replay.
    monkeypatch.setattr(evidence.nmap_runtime, "parse_isolated_xml",
                        lambda raw, *, deadline=None: parse_nmap_xml(raw)["results"])


def policy():
    return parse_policy({
        "schema_version": "1", "policy_version": "nmap-evidence-tests-v1",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": [contract.TOOL_ID, "http_probe"],
        "allowed_ports": [8080], "allowed_methods": ["GET"], "max_timeout_seconds": 5,
        "max_output_bytes": 16384, "max_targets": 1, "require_approval": False,
        "approval_ttl_seconds": 5,
    })


def store_at(path, case="a", *, runtime_sha256=RUNTIME_DIGEST):
    return evidence.NmapEvidenceStore(path, session_id=str(uuid4()), policy=policy(), case=case,
                                      owned_lab=identity(case, str(uuid4())), runtime_sha256=runtime_sha256)


def result(store, step):
    case = store._manifest["fixture_case"]
    if step == 1:
        raw = {
            "status": "succeeded", "results": [{"target": "127.0.0.1", "port": 8080, "state": "open"}],
            "bytes_received": len(XML), "truncated": False,
            "boundary_checks": dict.fromkeys(evidence._CHECKS, True),
            "raw_xml_base64": base64.b64encode(XML).decode(), "raw_stderr_base64": "",
            "provenance": {"runtime_sha256": RUNTIME_DIGEST, "runtime_manifest": copy.deepcopy(RUNTIME_MANIFEST),
                           "xml_sha256": hashlib.sha256(XML).hexdigest(),
                           "stderr_sha256": hashlib.sha256(b"").hexdigest(), "parser_version": PARSER_VERSION,
                           "exit_code": 0, "stop_reason": None},
        }
    elif step == 3 and case in {"d", "e"}:
        raw = {"status": "timeout" if case == "d" else "output_limit", "results": [],
               "bytes_received": 0, "truncated": False}
    else:
        status, body, _ = _response(contract.action(case, step)["parameters"]["path"])
        raw = {"status": "succeeded", "bytes_received": len(body) + 64, "truncated": False,
               "results": [{"target": "127.0.0.1", "port": 8080, "http_status": status,
                            "body": body.decode(), "bytes_received": len(body) + 64, "truncated": False,
                            "response_sha256": "a" * 64}]}
    return {**raw, "backend": contract.BACKEND,
            "owned_lab": {"identity": store._manifest["owned_lab"], "connection_count": step + 1,
                          "request_count": step - 1}}


def start(store, step):
    return store.start(parse_action(contract.action(store._manifest["fixture_case"], step)), policy(),
                       session_id=store._manifest["session_id"], session_step=step, backend=contract.BACKEND)


def close_receipt(store):
    return {**(store._lab_context or {"identity": store._manifest["owned_lab"],
                                     "connection_count": 0, "request_count": 0}), "status": "closed"}


def complete(path, case="a"):
    with store_at(path, case) as store:
        observation = _observation(1, None)
        for step in (1, 2, 3):
            if store.record_decision(step, observation).action is None:
                break
            raw = result(store, step)
            store.finish(start(store, step), raw, execution_status=raw["status"])
            observation = _observation(step + 1, {"execution_status": raw["status"], "untrusted_result": raw})
            if raw["status"] != "succeeded":
                break
        store.record_lab_closed(close_receipt(store))
        return store.finalize({
            "session_id": store._manifest["session_id"], "mode": "execute",
            "session_status": "stopped" if case in {"d", "e"} else "completed",
            "stop_reason": {"d": "action_timeout", "e": "action_output_limit"}.get(case, "coordinator_done"),
            "steps_attempted": step, "actions_succeeded": sum(row["execution_status"] == "succeeded" for row in store.records),
            "output_reserved_bytes": sum(row["action"]["parameters"]["max_output_bytes"] for row in store.records),
        })


@pytest.mark.parametrize("case,outcome", [
    ("a", "validated"), ("b", "not_demonstrated"), ("c", "inconclusive"),
    ("d", "inconclusive"), ("e", "inconclusive"), ("f", "inconclusive"),
])
def test_six_cases_replay_without_writes_and_without_assuming_exact_connect_counts(tmp_path, case, outcome):
    path = tmp_path / "evidence"
    report = complete(path, case)
    before = {item.name: (item.read_bytes(), item.stat().st_mtime_ns) for item in path.iterdir()}
    assert report["outcome"] == outcome
    assert report["integrity_issues"] == []
    assert evidence.inspect_evidence(path) == report
    assert before == {item.name: (item.read_bytes(), item.stat().st_mtime_ns) for item in path.iterdir()}
    assert report["runtime_sha256"] == RUNTIME_DIGEST
    assert report["records"][0]["observation"]["classification"] == "reachable"
    assert b"raw_xml_base64" not in (path / "report.md").read_bytes()
    assert b"<nmaprun" not in (path / "report.md").read_bytes()
    assert all(item.stat().st_mode & 0o077 == 0 for item in path.iterdir())


def mutate_result(path, change):
    events = [json.loads(line) for line in (path / "evidence.jsonl").read_text().splitlines()]
    event = next(row for row in events if row["event_type"] == "assessment_execution_finished")
    artifact = event["record"]["artifact"]
    target = path / artifact["filename"]
    result = json.loads(target.read_bytes())
    change(result)
    raw = contract.encode(result)
    target.write_bytes(raw)
    artifact.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    (path / "evidence.jsonl").write_bytes(b"\n".join(contract.encode(row) for row in events) + b"\n")


@pytest.mark.parametrize("change", [
    lambda result: result["results"][0].update(state="closed"),
    lambda result: result["provenance"].update(runtime_sha256="c" * 64),
    lambda result: result["provenance"]["runtime_manifest"]["files"][0].update(sha256="c" * 64),
    lambda result: result["provenance"].update(xml_sha256="c" * 64),
    lambda result: result["provenance"].update(exit_code=1),
    lambda result: result["provenance"].update(parser_version="new-parser"),
    lambda result: result["owned_lab"].update(request_count=1),
    lambda result: result["boundary_checks"].update(raw_sockets_blocked=False),
    lambda result: result.update(raw_xml_base64=base64.b64encode(b"<arbitrary/>").decode()),
])
def test_rehashing_an_artifact_cannot_forge_reachability_or_runtime_evidence(tmp_path, change):
    path = tmp_path / "evidence"
    complete(path)
    mutate_result(path, change)
    report = evidence.inspect_evidence(path)
    assert report["outcome"] == "inconclusive"
    assert "journal_or_artifact_incomplete" in report["integrity_issues"]


def test_xml_is_reparsed_even_when_its_hash_and_outer_artifact_hash_are_updated(tmp_path):
    path = tmp_path / "evidence"
    complete(path)

    def change(result):
        xml = XML.replace(b"127.0.0.1", b"127.0.0.2")
        result["raw_xml_base64"] = base64.b64encode(xml).decode()
        result["provenance"]["xml_sha256"] = hashlib.sha256(xml).hexdigest()

    mutate_result(path, change)
    assert evidence.inspect_evidence(path)["outcome"] == "inconclusive"


@pytest.mark.parametrize("runtime_digest", [None, "c" * 64])
def test_missing_or_replaced_host_runtime_pin_poison_completion(tmp_path, runtime_digest):
    with store_at(tmp_path / "evidence", runtime_sha256=runtime_digest) as store:
        store.record_decision(1, _observation(1, None))
        execution = start(store, 1)
        with pytest.raises(EvidenceUnavailable):
            store.finish(execution, result(store, 1), execution_status="succeeded")
        with pytest.raises(EvidenceUnavailable):
            store.record_decision(2, _observation(2, None))


def test_execution_without_a_durable_workflow_decision_is_rejected(tmp_path):
    with store_at(tmp_path / "evidence") as store:
        with pytest.raises(EvidenceUnavailable):
            start(store, 1)


def test_closed_nmap_port_stops_before_any_http_candidate(tmp_path):
    with store_at(tmp_path / "evidence") as store:
        store.record_decision(1, _observation(1, None))
        raw = result(store, 1)
        xml = XML.replace(b'state="open"', b'state="closed"')
        raw.update(raw_xml_base64=base64.b64encode(xml).decode(), bytes_received=len(xml))
        raw["provenance"]["xml_sha256"] = hashlib.sha256(xml).hexdigest()
        raw["results"][0]["state"] = "closed"
        store.finish(start(store, 1), raw, execution_status="succeeded")
        decision = store.record_decision(2, _observation(2, {"execution_status": "succeeded", "untrusted_result": raw}))
        assert decision.action is None and decision.reason == "nmap_reachability_not_established"


def test_dry_run_has_no_execution_evidence_and_no_http_followup(tmp_path):
    with store_at(tmp_path / "evidence", runtime_sha256=None) as store:
        assert store.record_decision(1, _observation(1, None)).action is not None
        frame = _observation(2, {"execution_status": "dry_run", "untrusted_result": {}})
        assert store.record_decision(2, frame).action is None
        store.record_lab_closed(close_receipt(store))
        report = store.finalize({"session_id": store._manifest["session_id"], "mode": "dry_run",
                                 "session_status": "completed", "stop_reason": "coordinator_done",
                                 "steps_attempted": 2, "actions_succeeded": 0, "output_reserved_bytes": 16384})
    assert report["outcome"] == "inconclusive"
    assert evidence.inspect_evidence(tmp_path / "evidence") == report


def test_provider_is_deterministic_bounded_and_cannot_be_rebound_or_reused(tmp_path):
    with store_at(tmp_path / "evidence") as store:
        provider = workflow.NmapProvider("a", store)
        control = ExecutionControl(time.monotonic() + 10)
        provider.bind_session(store._manifest["session_id"])
        with pytest.raises(ValueError):
            provider.bind_session(str(uuid4()))
        plan = json.loads(provider.propose(_observation(1, None), control=control))
        assert plan == {"schema_version": "1", "action": contract.action("a", 1), "done": False}
        stopped = json.loads(provider.propose(_observation(2, {"execution_status": "dry_run", "untrusted_result": {}}), control=control))
        assert stopped["action"] is None and stopped["done"] is True
        with pytest.raises(RuntimeError):
            provider.propose(_observation(3, None), control=control)


def test_forged_saved_report_and_missing_teardown_are_never_accepted(tmp_path):
    path = tmp_path / "evidence"
    complete(path)
    report_path = path / "report.json"
    report = json.loads(report_path.read_bytes())
    report["outcome"] = "inconclusive"
    report_path.write_bytes(contract.encode(report))
    assert "report_missing_or_mismatched" in evidence.inspect_evidence(path)["integrity_issues"]
    events = [json.loads(line) for line in (path / "evidence.jsonl").read_text().splitlines()]
    (path / "evidence.jsonl").write_bytes(b"\n".join(contract.encode(row) for row in events
        if row["event_type"] != "assessment_owned_lab_closed") + b"\n")
    result = evidence.inspect_evidence(path)
    assert result["outcome"] == "inconclusive" and "owned_lab_closure_missing" in result["integrity_issues"]
