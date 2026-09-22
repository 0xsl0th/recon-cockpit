"""Fixed TCP-to-HTTP evidence chains and read-only crash reconciliation."""

import hashlib
import json
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import evidence
from recon_cockpit.secure_agent.discovery_contract import discovery_action
from recon_cockpit.secure_agent.evidence import EvidenceStore, EvidenceUnavailable, inspect_assessment
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.worker import _response


def policy():
    return parse_policy({
        "schema_version": "1", "policy_version": "discovery-evidence-tests-v1",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": ["tcp_connect", "http_probe"],
        "allowed_ports": [8080], "allowed_methods": ["GET"],
        "max_timeout_seconds": 3, "max_output_bytes": 1024, "max_targets": 1,
        "require_approval": False, "approval_ttl_seconds": 5,
    })


def result(case, step, *, tcp_state="open"):
    if step == 1:
        return {"status": "succeeded", "bytes_received": 0, "truncated": False,
                "results": [{"target": "127.0.0.1", "port": 8080, "state": tcp_state}]}
    status, body, _headers = _response(discovery_action(case, step)["parameters"]["path"])
    return {"status": "succeeded", "bytes_received": len(body) + 64, "truncated": False,
            "results": [{"target": "127.0.0.1", "port": 8080, "http_status": status,
                         "body": body.decode("utf-8"), "bytes_received": len(body) + 64,
                         "truncated": False, "response_sha256": "a" * 64}]}


def start(store, step, case="a", *, action=None):
    return store.start(parse_action(action or discovery_action(case, step)), policy(),
                       session_id=store._manifest["session_id"], session_step=step,
                       backend="linux-authorized-discovery-fixture-executor-v1")


def summary(store, *, succeeded=3, steps=3, mode="execute"):
    return {"session_id": store._manifest["session_id"], "session_status": "completed",
            "stop_reason": "coordinator_done", "steps_attempted": steps,
            "actions_succeeded": succeeded, "output_reserved_bytes": steps * 1024, "mode": mode}


def complete(path, *, case="a", tcp_state="open"):
    with EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case=case, discovery=True) as store:
        for step in (1, 2, 3):
            store.finish(start(store, step, case), result(case, step, tcp_state=tcp_state),
                         execution_status="succeeded")
        return store.finalize(summary(store))


def journal_rows(path):
    return [json.loads(line) for line in (path / "evidence.jsonl").read_text().splitlines()]


def write_journal(path, rows):
    (path / "evidence.jsonl").write_text("\n".join(json.dumps(row) for row in rows) + "\n")


@pytest.mark.parametrize("case,outcome", [("a", "validated"), ("b", "not_demonstrated"), ("c", "inconclusive")])
def test_discovery_report_requires_and_references_all_three_observations(tmp_path, case, outcome):
    path = tmp_path / "discovery"
    report = complete(path, case=case)
    assert report["workflow"] == evidence.DISCOVERY_WORKFLOW
    assert report["outcome"] == outcome and report["integrity_issues"] == []
    assert report["execution"]["actions_succeeded"] == 3
    assert report["capability"]["limits"]["max_actions"] == 3
    http_executor = report["capability"]["capabilities"][1]["isolation"]["executor"]
    assert {record["backend"] for record in report["records"]} == {http_executor}
    assert [record["session_step"] for record in report["records"]] == [1, 2, 3]
    assert [record["action"]["tool_id"] for record in report["records"]] == ["tcp_connect", "http_probe", "http_probe"]
    assert report["records"][0]["observation"]["classification"] == "reachable"
    assert len(report["finding"]["evidence"]) == 3
    assert len(journal_rows(path)) == 7
    for record in report["records"]:
        artifact = record["artifact"]
        assert artifact["representation"] == evidence.DISCOVERY_REPRESENTATION
        assert artifact["sha256"] == hashlib.sha256((path / artifact["filename"]).read_bytes()).hexdigest()
    assert inspect_assessment(path) == report


@pytest.mark.parametrize("workflow,representation", [
    (evidence.WORKFLOW, evidence.DISCOVERY_REPRESENTATION),
    (evidence.DISCOVERY_WORKFLOW, evidence.REPRESENTATION),
    ("unreviewed-workflow", evidence.DISCOVERY_REPRESENTATION),
    (evidence.DISCOVERY_WORKFLOW, "arbitrary-result-json"),
])
def test_inspector_rejects_incompatible_workflow_manifest_pairs(tmp_path, workflow, representation):
    path = tmp_path / "discovery"
    complete(path)
    manifest = json.loads((path / "manifest.json").read_text())
    manifest.update(workflow=workflow, artifact_representation=representation)
    (path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(EvidenceUnavailable, match="^evidence_unavailable$"):
        inspect_assessment(path)


@pytest.mark.parametrize("omission", ["tcp_artifact", "tcp_journal", "last_http"])
def test_missing_execution_evidence_cannot_validate_the_discovery_workflow(tmp_path, omission):
    path = tmp_path / "discovery"
    report = complete(path)
    rows = journal_rows(path)
    if omission == "tcp_artifact":
        (path / report["records"][0]["artifact"]["filename"]).unlink()
    elif omission == "tcp_journal":
        write_journal(path, rows[2:])
    else:
        write_journal(path, rows[:4] + rows[-1:])
    inspected = inspect_assessment(path)
    assert inspected["outcome"] == "inconclusive"
    assert "journal_or_artifact_incomplete" in inspected["integrity_issues"]


def test_successful_http_results_cannot_replace_unreachable_tcp_evidence(tmp_path):
    path = tmp_path / "discovery"
    report = complete(path, tcp_state="closed")
    assert report["records"][0]["observation"]["classification"] != "reachable"
    assert [row["observation"]["classification"] for row in report["records"][1:]] == ["discovered", "exposed"]
    assert report["outcome"] == "inconclusive"
    assert report["reason"] == "discovery_or_execution_evidence_missing"
    assert inspect_assessment(path) == report
    rows = journal_rows(path)
    rows[1]["record"]["observation"].update(classification="reachable", reason="tcp_port_reachable")
    write_journal(path, rows)
    inspected = inspect_assessment(path)
    assert inspected["outcome"] == "inconclusive"
    assert "journal_or_artifact_incomplete" in inspected["integrity_issues"]


@pytest.mark.parametrize("step", [1, 2, 3])
def test_crash_inspection_preserves_completed_chain_and_never_restores_execution(tmp_path, step):
    path = tmp_path / "discovery"
    with EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case="a", discovery=True) as store:
        for completed_step in range(1, step):
            store.finish(start(store, completed_step), result("a", completed_step), execution_status="succeeded")
        execution_id = start(store, step)
    before = {item.name: item.read_bytes() for item in path.iterdir()}
    inspected = inspect_assessment(path)
    assert inspected["outcome"] == "inconclusive"
    assert inspected["records"][-1]["execution_id"] == execution_id
    assert inspected["records"][-1]["execution_status"] == "started"
    assert len(inspected["finding"]["evidence"]) == step - 1
    assert set(inspected["integrity_issues"]) == {"assessment_closure_missing", "execution_completion_unknown"}
    assert {item.name: item.read_bytes() for item in path.iterdir()} == before
    with pytest.raises(EvidenceUnavailable):
        EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case="a", discovery=True)


@pytest.mark.parametrize("failure", ["artifact", "completion", "closure"])
def test_failed_tcp_evidence_writes_latch_and_remain_reconcilable(tmp_path, monkeypatch, failure):
    path = tmp_path / "discovery"
    with EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case="a", discovery=True) as store:
        original_emit, original_write = store._emit, store._write_new

        def emit(value):
            if value["event_type"] == {"completion": "assessment_execution_finished", "closure": "assessment_finished"}.get(failure):
                raise OSError("PRIVATE-ERROR")
            return original_emit(value)

        def write(name, raw, limit):
            if failure == "artifact" and name.startswith("result-"):
                raise OSError("PRIVATE-ERROR")
            return original_write(name, raw, limit)

        monkeypatch.setattr(store, "_emit", emit)
        monkeypatch.setattr(store, "_write_new", write)
        with pytest.raises(EvidenceUnavailable, match="^evidence_unavailable$"):
            store.finish(start(store, 1), result("a", 1), execution_status="succeeded")
            store.finalize(summary(store, steps=1, succeeded=1))
        with pytest.raises(EvidenceUnavailable):
            start(store, 2)
    report = inspect_assessment(path)
    assert report["outcome"] == "inconclusive"
    assert "assessment_closure_missing" in report["integrity_issues"]
    assert "PRIVATE-ERROR" not in json.dumps(report)
    assert not (path / "report.json").exists()


@pytest.mark.parametrize("invalid", ["http_first", "fourth_step", "unknown_selector"])
def test_store_rejects_actions_outside_fixed_three_step_workflow(tmp_path, invalid):
    if invalid == "unknown_selector":
        with pytest.raises(EvidenceUnavailable):
            EvidenceStore(tmp_path / "discovery", session_id=str(uuid4()), policy=policy(), case="a", discovery="yes")
        return
    with EvidenceStore(tmp_path / "discovery", session_id=str(uuid4()), policy=policy(), case="a", discovery=True) as store:
        if invalid == "fourth_step":
            for step in (1, 2, 3):
                store.finish(start(store, step), result("a", step), execution_status="succeeded")
        with pytest.raises(EvidenceUnavailable):
            start(store, 4 if invalid == "fourth_step" else 1, action=discovery_action("a", 2))


@pytest.mark.parametrize("field,value", [("steps_attempted", 4), ("actions_succeeded", 4), ("output_reserved_bytes", 3073)])
def test_discovery_summary_bounds_fail_closed_for_writer_and_reader(tmp_path, field, value):
    path = tmp_path / "discovery"
    complete(path)
    rows = journal_rows(path)
    rows[-1]["summary"][field] = value
    write_journal(path, rows)
    report = inspect_assessment(path)
    assert report["outcome"] == "inconclusive" and report["integrity_issues"]
    with EvidenceStore(tmp_path / "writer", session_id=str(uuid4()), policy=policy(), case="a", discovery=True) as store:
        invalid = {**summary(store, steps=0, succeeded=0), field: value}
        with pytest.raises(EvidenceUnavailable):
            store.finalize(invalid)


def test_discovery_dry_run_retains_no_execution_or_finding_evidence(tmp_path):
    path = tmp_path / "discovery"
    with EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case="a", discovery=True) as store:
        report = store.finalize(summary(store, steps=2, succeeded=0, mode="dry_run"))
    assert report["outcome"] == "inconclusive" and report["reason"] == "dry_run_has_no_execution_evidence"
    assert report["records"] == [] and report["finding"]["evidence"] == []
    assert inspect_assessment(path) == report


@pytest.mark.parametrize('field,value', [('output_reserved_bytes', 0), ('steps_attempted', 2)])
def test_summary_reconciles_actual_executions_for_writer_and_reader(tmp_path, field, value):
    path = tmp_path / 'evidence'
    with EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case='a', discovery=True) as store:
        for step in (1, 2, 3):
            status = 'succeeded' if step < 3 else 'failed'
            store.finish(start(store, step), result('a', step), execution_status=status)
        valid = summary(store, succeeded=2)
        store.finalize(valid)
    rows = journal_rows(path)
    rows[-1]['summary'][field] = value
    write_journal(path, rows)
    inspected = inspect_assessment(path)
    assert 'journal_or_artifact_incomplete' in inspected['integrity_issues']
    assert inspected['outcome'] == 'inconclusive'
    with EvidenceStore(tmp_path / 'writer', session_id=str(uuid4()), policy=policy(), case='a', discovery=True) as store:
        for step in (1, 2, 3):
            store.finish(start(store, step), result('a', step),
                         execution_status='succeeded' if step < 3 else 'failed')
        with pytest.raises(EvidenceUnavailable):
            store.finalize({**summary(store, succeeded=2), field: value})


def test_summary_allows_reservation_for_blocked_action_without_execution(tmp_path):
    path = tmp_path / 'evidence'
    with EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case='a', discovery=True) as store:
        store.finish(start(store, 1), result('a', 1), execution_status='succeeded')
        report = store.finalize({**summary(store, succeeded=1, steps=2),
                                 'session_status': 'stopped', 'stop_reason': 'action_blocked'})
    assert report['integrity_issues'] == []
    assert report['execution']['output_reserved_bytes'] == 2048
    assert inspect_assessment(path) == report
