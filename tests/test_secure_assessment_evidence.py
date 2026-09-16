"""Durable evidence and read-only reconciliation; no isolation claim here."""

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import evidence
from recon_cockpit.secure_agent.assessment_contract import assessment_action
from recon_cockpit.secure_agent.evidence import EvidenceStore, EvidenceUnavailable, inspect_assessment
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session import _observation
from recon_cockpit.secure_agent.worker import _response


def policy():
    return parse_policy({
        "schema_version": "1", "policy_version": "evidence-tests-v1", "allowed_targets": ["127.0.0.1/32"],
        "allowed_tools": ["http_probe"], "allowed_ports": [8080], "allowed_methods": ["GET"],
        "max_timeout_seconds": 3, "max_output_bytes": 1024, "max_targets": 1,
        "require_approval": False, "approval_ttl_seconds": 5,
    })


def result(case, step):
    action = assessment_action(case, step)
    status, body, _headers = _response(action["parameters"]["path"])
    return {"status": "succeeded", "bytes_received": len(body) + 64, "truncated": False,
            "results": [{"target": "127.0.0.1", "port": 8080, "http_status": status,
                         "body": body.decode("utf-8"), "bytes_received": len(body) + 64,
                         "truncated": False, "response_sha256": "a" * 64}]}


def start(store, step, case="a", *, action=None):
    action = parse_action(assessment_action(case, step)) if action is None else action
    return store.start(action, policy(), session_id=store._manifest["session_id"],
                       session_step=step, backend="linux-authorized-fixture-executor-v1")


def summary(store, *, mode="execute", succeeded=2, status="completed"):
    return {"session_id": store._manifest["session_id"], "session_status": status,
            "stop_reason": "coordinator_done" if status == "completed" else "action_failed",
            "steps_attempted": 2, "actions_succeeded": succeeded,
            "output_reserved_bytes": 2048, "mode": mode}


def complete(path, *, case="a"):
    with EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case=case) as store:
        for step in (1, 2):
            key = start(store, step, case)
            store.finish(key, result(case, step), execution_status="succeeded")
        report = store.finalize(summary(store))
    return report


def rows(path):
    return [json.loads(line) for line in (path / "evidence.jsonl").read_text().splitlines()]


@pytest.mark.parametrize("case,outcome", [("a", "validated"), ("b", "not_demonstrated"), ("c", "inconclusive")])
def test_reports_recompute_from_private_artifacts_and_link_both_executions(tmp_path, case, outcome):
    path = tmp_path / "assessment"
    report = complete(path, case=case)
    assert report["outcome"] == outcome
    assert report["finding"]["review_status"] == "pending_operator_review"
    assert len(report["finding"]["evidence"]) == 2
    assert report["integrity_issues"] == []
    assert inspect_assessment(path) == report
    assert stat.S_IMODE(path.stat().st_mode) == 0o700
    for item in path.iterdir():
        assert stat.S_IMODE(item.stat().st_mode) == 0o600
    assert len({row["execution_id"] for row in report["records"]}) == 2
    for row in report["records"]:
        assert row["execution_id"] != row["action"]["action_id"]
        assert "rationale" not in row["action"]
        raw = (path / row["artifact"]["filename"]).read_bytes()
        assert row["artifact"]["sha256"] == hashlib.sha256(raw).hexdigest()
        assert row["artifact"]["bytes"] == len(raw)
        assert row["artifact"]["representation"] == evidence.REPRESENTATION
        assert row["artifact"]["sha256"] != json.loads(raw)["results"][0]["response_sha256"]
    rendered = (path / "report.md").read_text() + (path / "report.json").read_text()
    assert "diagnostics_path" not in rendered
    assert "internal_service" not in rendered
    assert '"body"' not in rendered + (path / "evidence.jsonl").read_text()


def test_observation_hash_binds_exact_authority_feedback_and_safe_records_are_copies(tmp_path):
    with EvidenceStore(tmp_path / "assessment", session_id=str(uuid4()), policy=policy(), case="a") as store:
        raw = result("a", 1)
        key = start(store, 1)
        store.finish(key, raw, execution_status="succeeded")
        expected = _observation(2, {"execution_status": "succeeded", "untrusted_result": raw})
        record = store.records[0]
        assert record["authority_observation_sha256"] == hashlib.sha256(expected).hexdigest()
        record["observation"]["classification"] = "forged"
        record["action"]["target"] = "203.0.113.1"
        assert store.records[0]["observation"]["classification"] == "discovered"
        assert store.records[0]["action"]["target"] == "127.0.0.1"


def test_raw_hostile_content_never_becomes_report_or_journal_markup(tmp_path):
    path = tmp_path / "assessment"
    hostile = '<script>alert(1)</script>\x1b[31m [click](https://example.invalid/) ``` PRIVATE-MARKER'
    with EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case="a") as store:
        key = start(store, 1)
        raw = result("a", 1)
        raw["results"][0]["body"] = hostile
        store.finish(key, raw, execution_status="succeeded")
        report = store.finalize(summary(store, succeeded=1))
    assert report["outcome"] == "inconclusive"
    assert inspect_assessment(path) == report
    safe = (path / "report.md").read_text() + (path / "report.json").read_text() + (path / "evidence.jsonl").read_text()
    assert "PRIVATE-MARKER" not in safe and "<script>" not in safe and "https://example.invalid/" not in safe
    artifact = path / report["records"][0]["artifact"]["filename"]
    assert json.loads(artifact.read_text())["results"][0]["body"] == hostile


def test_dry_run_report_and_empty_directory_inspection_do_not_claim_findings(tmp_path):
    path = tmp_path / "assessment"
    with EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case="a") as store:
        before = inspect_assessment(path)
        assert before["outcome"] == "inconclusive"
        assert "assessment_closure_missing" in before["integrity_issues"]
        report = store.finalize(summary(store, mode="dry_run", succeeded=0))
    assert report["outcome"] == "inconclusive"
    assert report["reason"] == "dry_run_has_no_execution_evidence"
    assert inspect_assessment(path) == report


def test_started_without_finished_is_completion_unknown_and_inspection_does_not_write(tmp_path):
    path = tmp_path / "assessment"
    with EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case="a") as store:
        key = start(store, 1)
    contents = {item.name: item.read_bytes() for item in path.iterdir()}
    report = inspect_assessment(path)
    assert report["outcome"] == "inconclusive"
    assert set(report["integrity_issues"]) == {"assessment_closure_missing", "execution_completion_unknown"}
    assert report["records"][0]["execution_id"] == key
    assert report["finding"]["evidence"] == []
    assert {item.name: item.read_bytes() for item in path.iterdir()} == contents
    with pytest.raises(EvidenceUnavailable):
        EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case="a")


@pytest.mark.parametrize("mutation", ["missing", "digest", "symlink", "hardlink", "fifo", "public", "oversize"])
def test_reader_rejects_unsafe_or_inconsistent_artifacts(tmp_path, mutation):
    path = tmp_path / "assessment"
    original = complete(path)
    artifact = path / original["records"][0]["artifact"]["filename"]
    if mutation == "missing":
        artifact.unlink()
    elif mutation == "digest":
        artifact.write_bytes(b"{}")
    elif mutation == "symlink":
        raw = artifact.read_bytes()
        artifact.unlink()
        other = tmp_path / "outside-artifact"
        other.write_bytes(raw)
        artifact.symlink_to(other)
    elif mutation == "hardlink":
        os.link(artifact, path / "alias.json")
    elif mutation == "fifo":
        artifact.unlink()
        os.mkfifo(artifact, 0o600)
    elif mutation == "public":
        artifact.chmod(0o644)
    else:
        artifact.write_bytes(b" " * (evidence.MAX_ARTIFACT_BYTES + 1))
    report = inspect_assessment(path)
    assert report["outcome"] == "inconclusive"
    assert "journal_or_artifact_incomplete" in report["integrity_issues"]


@pytest.mark.parametrize("mutation", ["partial_tail", "missing_close", "duplicate_step", "wrong_session", "forged_path", "forged_observation", "orphan", "report_missing", "report_changed"])
def test_reader_reconciles_journal_and_report_faults_without_trusting_claims(tmp_path, mutation):
    path = tmp_path / "assessment"
    complete(path)
    records = rows(path)
    journal = path / "evidence.jsonl"
    if mutation == "partial_tail":
        journal.write_bytes(journal.read_bytes()[:-8])
    elif mutation == "missing_close":
        journal.write_text("\n".join(json.dumps(row) for row in records[:-1]) + "\n")
    elif mutation in {"duplicate_step", "wrong_session", "forged_path", "forged_observation"}:
        if mutation == "duplicate_step":
            records[2]["record"]["session_step"] = 1
        elif mutation == "wrong_session":
            records[1]["session_id"] = str(uuid4())
        elif mutation == "forged_path":
            records[1]["record"]["artifact"]["filename"] = "../../outside-secret"
        else:
            records[1]["record"]["observation"]["classification"] = "exposed"
        journal.write_text("\n".join(json.dumps(row) for row in records) + "\n")
    elif mutation == "orphan":
        (path / "orphan.json").write_text("{}")
    elif mutation == "report_missing":
        (path / "report.md").unlink()
    else:
        (path / "report.json").write_text('{"outcome":"validated"}')
    report = inspect_assessment(path)
    assert report["outcome"] == "inconclusive" and report["integrity_issues"]


@pytest.mark.parametrize("failure_point", ["start", "artifact", "completion", "report"])
def test_write_failures_latch_and_preserve_reconcilable_state(tmp_path, monkeypatch, failure_point):
    path = tmp_path / "assessment"
    with EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case="a") as store:
        original_emit, original_write = store._emit, store._write_new

        def emit(value):
            if ((failure_point == "start" and value["event_type"] == "assessment_execution_started")
                    or (failure_point == "completion" and value["event_type"] == "assessment_execution_finished")):
                raise OSError("PRIVATE-STORAGE-ERROR")
            original_emit(value)

        def write(name, raw, limit):
            if (failure_point == "artifact" and name.startswith("result-")) or (failure_point == "report" and name == "report.md"):
                raise OSError("PRIVATE-STORAGE-ERROR")
            original_write(name, raw, limit)

        monkeypatch.setattr(store, "_emit", emit)
        monkeypatch.setattr(store, "_write_new", write)
        with pytest.raises(EvidenceUnavailable, match="^evidence_unavailable$"):
            key = start(store, 1)
            store.finish(key, result("a", 1), execution_status="succeeded")
            store.finalize(summary(store, succeeded=1))
        with pytest.raises(EvidenceUnavailable):
            start(store, 2)
    report = inspect_assessment(path)
    assert report["outcome"] == "inconclusive"
    expected_issue = "report_missing_or_mismatched" if failure_point == "report" else "assessment_closure_missing"
    assert expected_issue in report["integrity_issues"]
    assert "PRIVATE-STORAGE-ERROR" not in json.dumps(report)


def test_failed_durable_closure_never_publishes_a_validated_report(tmp_path, monkeypatch):
    path = tmp_path / "assessment"
    with EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case="a") as store:
        for step in (1, 2):
            store.finish(start(store, step), result("a", step), execution_status="succeeded")
        original = store._journal.emit

        def fail_closure(event):
            if event["event_type"] == "assessment_finished":
                raise OSError("closure failed")
            original(event)

        monkeypatch.setattr(store._journal, "emit", fail_closure)
        with pytest.raises(EvidenceUnavailable):
            store.finalize(summary(store))
    assert not (path / "report.json").exists() and not (path / "report.md").exists()
    inspected = inspect_assessment(path)
    assert inspected["outcome"] == "inconclusive"
    assert "assessment_closure_missing" in inspected["integrity_issues"]


def test_artifacts_are_exclusive_and_store_cannot_resume_after_close(tmp_path):
    path = tmp_path / "assessment"
    store = EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case="a")
    key = start(store, 1)
    artifact = path / ("result-" + key + ".json")
    artifact.write_text("preserve-me")
    with pytest.raises(EvidenceUnavailable):
        store.finish(key, result("a", 1), execution_status="succeeded")
    assert artifact.read_text() == "preserve-me"
    store.close()
    with pytest.raises(EvidenceUnavailable):
        start(store, 2)


@pytest.mark.parametrize("mutation", ["wrong_session", "wrong_policy", "wrong_step", "wrong_action", "unfinished", "oversized_result"])
def test_evidence_contract_rejects_out_of_workflow_or_unbounded_records(tmp_path, mutation):
    with EvidenceStore(tmp_path / "assessment", session_id=str(uuid4()), policy=policy(), case="a") as store:
        with pytest.raises(EvidenceUnavailable):
            if mutation in {"unfinished", "oversized_result"}:
                key = start(store, 1)
                if mutation == "unfinished":
                    start(store, 2)
                else:
                    raw = result("a", 1)
                    raw["results"][0]["body"] = "x" * evidence.MAX_ARTIFACT_BYTES
                    store.finish(key, raw, execution_status="succeeded")
            else:
                action = assessment_action("a", 1)
                if mutation == "wrong_action":
                    action["parameters"]["path"] = "/injection"
                configured_policy = policy()
                if mutation == "wrong_policy":
                    configured_policy = parse_policy({**policy().to_dict(), "policy_version": "other"})
                store.start(parse_action(action), configured_policy,
                            session_id=str(uuid4()) if mutation == "wrong_session" else store._manifest["session_id"],
                            session_step=2 if mutation == "wrong_step" else 1,
                            backend="linux-authorized-fixture-executor-v1")


def test_directory_symlinks_public_mode_and_replacement_are_rejected(tmp_path):
    path = tmp_path / "assessment"
    with EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case="a") as store:
        alias = tmp_path / "alias"
        alias.symlink_to(path, target_is_directory=True)
        with pytest.raises(EvidenceUnavailable):
            inspect_assessment(alias)
        path.chmod(0o755)
        with pytest.raises(EvidenceUnavailable):
            inspect_assessment(path)
        path.chmod(0o700)
        moved = tmp_path / "moved"
        path.rename(moved)
        path.mkdir(mode=0o700)
        with pytest.raises(EvidenceUnavailable):
            start(store, 1)
    assert list(path.iterdir()) == []


def test_finalize_cannot_claim_extra_success_or_be_reused(tmp_path):
    path = tmp_path / "assessment"
    with EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case="a") as store:
        with pytest.raises(EvidenceUnavailable):
            store.finalize(summary(store))
    other = tmp_path / "finished"
    with EvidenceStore(other, session_id=str(uuid4()), policy=policy(), case="a") as store:
        store.finalize(summary(store, mode="dry_run", succeeded=0))
        with pytest.raises(EvidenceUnavailable):
            store.finalize(summary(store, mode="dry_run", succeeded=0))


@pytest.mark.parametrize("location", ["journal", "report"])
def test_reader_detects_boolean_integer_type_substitution(tmp_path, location):
    path = tmp_path / "assessment"
    complete(path)
    if location == "journal":
        records = rows(path)
        records[1]["record"]["result_metadata"]["truncated"] = 0
        (path / "evidence.jsonl").write_text("\n".join(json.dumps(row) for row in records) + "\n")
    else:
        report = json.loads((path / "report.json").read_text())
        report["records"][0]["result_metadata"]["truncated"] = 0
        (path / "report.json").write_text(json.dumps(report))
    inspected = inspect_assessment(path)
    assert inspected["outcome"] == "inconclusive" and inspected["integrity_issues"]


def test_inspection_stops_directory_enumeration_at_the_file_bound(tmp_path, monkeypatch):
    path = tmp_path / "assessment"
    complete(path)
    seen = []

    class Entries:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def __iter__(self):
            for number in range(1000000):
                seen.append(number)
                yield type("Entry", (), {"name": "untrusted-" + str(number)})()

    monkeypatch.setattr(evidence.os, "scandir", lambda _fd: Entries())
    with pytest.raises(EvidenceUnavailable):
        inspect_assessment(path)
    assert len(seen) == 13
