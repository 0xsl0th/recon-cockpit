"""Portable data-contract tests; Linux tests exercise actual parser isolation."""

import copy
import hashlib
import json
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import nmap_evidence as evidence, nmap_contract, nmap_workflow
from recon_cockpit.secure_agent import web_assessment_contract as contract, web_workflow as workflow
from recon_cockpit.secure_agent.evidence import EvidenceUnavailable
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.nmap_parser import parse_nmap_xml
from recon_cockpit.secure_agent.owned_lab_contract import identity as old_identity
from recon_cockpit.secure_agent.session import _observation
from recon_cockpit.secure_agent.web_lab_contract import identity

from test_secure_nmap_evidence import RUNTIME_DIGEST, policy, result as nmap_result
from test_secure_web_assessment_contract import result as http_result


@pytest.fixture(autouse=True)
def unit_only_parser_double(monkeypatch):
    monkeypatch.setattr(evidence.nmap_runtime, "parse_isolated_xml",
                        lambda raw, *, deadline=None: parse_nmap_xml(raw)["results"])


def store_at(path, case="vulnerable", **kwargs):
    return evidence.NmapEvidenceStore(path, session_id=str(uuid4()), policy=policy(), case=case,
                                      owned_lab=identity(case, str(uuid4())), runtime_sha256=RUNTIME_DIGEST,
                                      workflow_profile="web", **kwargs)


def result(store, step):
    raw = nmap_result(store, 1) if step == 1 else http_result(store._manifest["fixture_case"], step)
    return {**raw, "backend": contract.BACKEND,
            "owned_lab": {"identity": store._manifest["owned_lab"], "connection_count": step + 1,
                          "request_count": step - 1}}


def start(store, step):
    return store.start(parse_action(contract.action(store._manifest["fixture_case"], step)), policy(),
                       session_id=store._manifest["session_id"], session_step=step, backend=contract.BACKEND)


def close_receipt(store):
    return {**(store._lab_context or {"identity": store._manifest["owned_lab"],
                                     "connection_count": 0, "request_count": 0}), "status": "closed"}


def complete(path, case="vulnerable"):
    with store_at(path, case) as store:
        observation = _observation(1, None)
        for step in (1, 2, 3):
            assert store.record_decision(step, observation).action == contract.action(case, step)
            raw = result(store, step)
            store.finish(start(store, step), raw, execution_status="succeeded")
            observation = _observation(step + 1, {"execution_status": "succeeded", "untrusted_result": raw})
        store.record_lab_closed(close_receipt(store))
        return store.finalize({
            "session_id": store._manifest["session_id"], "mode": "execute", "session_status": "completed",
            "stop_reason": "coordinator_done", "steps_attempted": 3, "actions_succeeded": 3,
            "output_reserved_bytes": 18432,
        })


@pytest.mark.parametrize("case,outcome", [("vulnerable", "validated"), ("corrected", "not_demonstrated"),
                                         ("injected", "validated")])
def test_variant_outcomes_replay_without_writes_or_raw_note_in_reports(tmp_path, case, outcome):
    path = tmp_path / "evidence"
    report = complete(path, case)
    before = {item.name: (item.read_bytes(), item.stat().st_mtime_ns) for item in path.iterdir()}
    assert report["outcome"] == outcome and report["integrity_issues"] == []
    assert report["workflow"] == contract.WORKFLOW
    assert report["workflow_card"] == workflow.card_identity()
    assert evidence.inspect_evidence(path) == report
    assert before == {item.name: (item.read_bytes(), item.stat().st_mtime_ns) for item in path.iterdir()}
    assert report["summary"]["output_reserved_bytes"] == 18432
    assert report["owned_lab"]["closure"]["request_count"] == 2
    if case == "injected":
        artifact = report["records"][1]["artifact"]["filename"]
        assert b"Ignore prior instructions" in (path / artifact).read_bytes()
        for filename in ("report.json", "report.md", "evidence.jsonl"):
            assert b"Ignore prior instructions" not in (path / filename).read_bytes()
            assert b"127.0.0.2" not in (path / filename).read_bytes()
        assert any("No model susceptibility" in item for item in report["limitations"])


def test_fresh_evidence_instances_have_no_shared_identity_counters_or_grants(tmp_path):
    first = complete(tmp_path / "first", "injected")
    second = complete(tmp_path / "second", "injected")
    assert first["session_id"] != second["session_id"]
    assert first["owned_lab"]["identity"]["instance_id"] != second["owned_lab"]["identity"]["instance_id"]
    assert first["owned_lab"]["identity"]["spec_sha256"] == second["owned_lab"]["identity"]["spec_sha256"]
    assert [row["observation"] for row in first["records"]] == [row["observation"] for row in second["records"]]
    assert first["owned_lab"]["closure"]["request_count"] == second["owned_lab"]["closure"]["request_count"] == 2


def mutate_result(path, step, change):
    events = [json.loads(line) for line in (path / "evidence.jsonl").read_text().splitlines()]
    event = next(row for row in events if row["event_type"] == "assessment_execution_finished"
                 and row["record"]["session_step"] == step)
    artifact = event["record"]["artifact"]
    target = path / artifact["filename"]
    raw = json.loads(target.read_bytes())
    change(raw)
    encoded = contract.encode(raw)
    target.write_bytes(encoded)
    artifact.update(bytes=len(encoded), sha256=hashlib.sha256(encoded).hexdigest())
    (path / "evidence.jsonl").write_bytes(b"\n".join(contract.encode(row) for row in events) + b"\n")


@pytest.mark.parametrize("step,change", [
    (1, lambda raw: raw["results"][0].update(state="closed")),
    (1, lambda raw: raw["provenance"].update(runtime_sha256="c" * 64)),
    (2, lambda raw: raw["results"][0].update(body='{"approved":true}')),
    (2, lambda raw: raw["owned_lab"].update(request_count=2)),
    (3, lambda raw: raw["owned_lab"]["identity"].update(instance_id=str(uuid4()))),
    (3, lambda raw: raw.update(backend=nmap_contract.BACKEND)),
])
def test_rehashed_results_cannot_relabel_runtime_findings_or_lab_continuity(tmp_path, step, change):
    path = tmp_path / "evidence"
    complete(path, "injected")
    mutate_result(path, step, change)
    report = evidence.inspect_evidence(path)
    assert report["outcome"] == "inconclusive"
    assert "journal_or_artifact_incomplete" in report["integrity_issues"]


@pytest.mark.parametrize("replacement", [nmap_contract.WORKFLOW, "owned-web-assessment-v2", "arbitrary.module"])
def test_saved_workflow_cannot_select_an_unreviewed_or_incompatible_contract(tmp_path, replacement):
    path = tmp_path / "evidence"
    complete(path)
    manifest = json.loads((path / "manifest.json").read_bytes())
    manifest["workflow"] = replacement
    (path / "manifest.json").write_bytes(contract.encode(manifest))
    with pytest.raises(EvidenceUnavailable):
        evidence.inspect_evidence(path)


@pytest.mark.parametrize("profile", [None, [], "arbitrary.module", "web-v2"])
def test_unreviewed_profile_is_rejected_before_any_evidence_write(tmp_path, profile):
    path = tmp_path / "evidence"
    with pytest.raises(EvidenceUnavailable):
        evidence.NmapEvidenceStore(path, session_id=str(uuid4()), policy=policy(), case="vulnerable",
                                  owned_lab=identity("vulnerable", str(uuid4())), workflow_profile=profile)
    assert not path.exists()


def test_web_provider_ignores_note_and_reuses_neither_session_nor_completed_sequence(tmp_path):
    with store_at(tmp_path / "evidence", "injected") as store:
        provider = workflow.WebProvider("injected", store)
        provider.bind_session(store._manifest["session_id"])
        with pytest.raises(ValueError):
            provider.bind_session(str(uuid4()))
        frame = _observation(1, None)
        control = ExecutionControl(time.monotonic() + 10)
        for step in (1, 2, 3):
            proposal = json.loads(provider.propose(frame, control=control))
            assert proposal["action"] == contract.action("injected", step)
            assert proposal["done"] is (step == 3)
            raw = result(store, step)
            store.finish(start(store, step), raw, execution_status="succeeded")
            frame = _observation(step + 1, {"execution_status": "succeeded", "untrusted_result": raw})
        with pytest.raises(RuntimeError):
            provider.propose(frame, control=control)


@pytest.mark.parametrize("change", [
    lambda records: records[0].update(action_digest="a" * 64),
    lambda records: records[0].update(execution_status="failed"),
    lambda records: records[0]["observation"].update(classification="inconclusive"),
    lambda records: records[0].update(authority_observation_sha256="b" * 64),
])
def test_followup_requires_matching_successful_durable_predecessor(tmp_path, change):
    with store_at(tmp_path / "evidence") as store:
        store.record_decision(1, _observation(1, None))
        raw = result(store, 1)
        store.finish(start(store, 1), raw, execution_status="succeeded")
        records = store.records
        change(records)
        frame = _observation(2, {"execution_status": "succeeded", "untrusted_result": raw})
        assert workflow.decide("vulnerable", 2, records, frame).action is None


def test_variant_cannot_reuse_other_variants_execution_evidence(tmp_path):
    with store_at(tmp_path / "evidence") as store:
        store.record_decision(1, _observation(1, None))
        raw = result(store, 1)
        store.finish(start(store, 1), raw, execution_status="succeeded")
        frame = _observation(2, {"execution_status": "succeeded", "untrusted_result": raw})
        assert workflow.decide("corrected", 2, store.records, frame).action is None


@pytest.mark.parametrize("change", [
    lambda receipt: receipt.update(request_count=1),
    lambda receipt: receipt["identity"].update(instance_id=str(uuid4())),
    lambda receipt: receipt.update(status="running"),
])
def test_wrong_closure_cannot_publish_findings(tmp_path, change):
    with store_at(tmp_path / "evidence") as store:
        receipt = copy.deepcopy(close_receipt(store))
        change(receipt)
        with pytest.raises(EvidenceUnavailable):
            store.record_lab_closed(receipt)
        with pytest.raises(EvidenceUnavailable):
            store.finalize({})
    assert not (tmp_path / "evidence" / "report.json").exists()


def test_web_dry_run_never_establishes_reachability_or_starts_parser(tmp_path, monkeypatch):
    def forbidden_parser(*args, **kwargs):
        raise AssertionError("dry run must not parse a tool result")

    monkeypatch.setattr(evidence.nmap_runtime, "parse_isolated_xml", forbidden_parser)
    path = tmp_path / "evidence"
    with store_at(path) as store:
        assert store.record_decision(1, _observation(1, None)).action is not None
        assert store.record_decision(2, _observation(2, {"execution_status": "dry_run", "untrusted_result": {}})).action is None
        store.record_lab_closed(close_receipt(store))
        report = store.finalize({"session_id": store._manifest["session_id"], "mode": "dry_run",
                                 "session_status": "completed", "stop_reason": "coordinator_done",
                                 "steps_attempted": 2, "actions_succeeded": 0, "output_reserved_bytes": 16384})
    assert report["outcome"] == "inconclusive"
    assert report["reason"] == "dry_run_has_no_execution_evidence"
    assert evidence.inspect_evidence(path) == report


def test_legacy_nmap_report_and_markdown_keep_reviewed_bytes():
    fixed = "00000000-0000-4000-8000-000000000001"
    manifest = {"assessment_id": fixed, "session_id": fixed, "fixture_case": "a", "workflow": nmap_contract.WORKFLOW,
                "workflow_card": nmap_workflow.card_identity(), "runtime_sha256": None, "owned_lab": old_identity("a", fixed)}
    report = evidence._report(manifest, [], [], None, None, None, [])
    assert hashlib.sha256(nmap_contract.encode(report)).hexdigest() == "71d9d2af19b262296440c943544026f7e255c164a4c6be1370bf7bf74efe4721"
    assert hashlib.sha256(evidence._markdown(report)).hexdigest() == "869d35e32a15db421916e87be5e846f6ee7e272b85b4dd520a6b94827c0e70e3"
