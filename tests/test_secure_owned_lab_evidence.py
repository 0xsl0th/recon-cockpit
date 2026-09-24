"""Persistent service provenance, teardown, replay and old bundle compatibility."""

import copy
import hashlib
import json
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import evidence, owned_lab_contract as contract, workflow
from recon_cockpit.secure_agent.discovery_contract import discovery_action, parse_observation
from recon_cockpit.secure_agent.evidence import EvidenceStore, EvidenceUnavailable, inspect_assessment
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session import _observation
from recon_cockpit.secure_agent.worker import _response


def policy():
    return parse_policy({
        "schema_version": "1", "policy_version": "owned-lab-evidence-tests-v1",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": ["tcp_connect", "http_probe"],
        "allowed_ports": [8080], "allowed_methods": ["GET"], "max_timeout_seconds": 3,
        "max_output_bytes": 1024, "max_targets": 1, "require_approval": False,
        "approval_ttl_seconds": 5,
    })


def store_at(path, *, case="a"):
    return EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case=case,
                         discovery=True, workflow=True,
                         owned_lab=contract.identity(case, str(uuid4())))


def result(store, step):
    case = store._manifest["fixture_case"]
    if step == 1:
        value = {"status": "succeeded", "bytes_received": 0, "truncated": False,
                 "results": [{"target": "127.0.0.1", "port": 8080, "state": "open"}]}
    elif step == 3 and case in {"d", "e"}:
        value = {"status": "timeout" if case == "d" else "output_limit", "bytes_received": 0,
                 "truncated": False, "results": []}
    else:
        status, body, _ = _response(discovery_action(case, step)["parameters"]["path"])
        value = {"status": "succeeded", "bytes_received": len(body) + 64, "truncated": False,
                 "results": [{"target": "127.0.0.1", "port": 8080, "http_status": status,
                              "body": body.decode(), "bytes_received": len(body) + 64,
                              "truncated": False, "response_sha256": "a" * 64}]}
    return {**value, "backend": contract.BACKEND,
            "owned_lab": {"identity": copy.deepcopy(store._manifest["owned_lab"]),
                          "connection_count": step, "request_count": step - 1}}


def start(store, step, *, backend=contract.BACKEND):
    return store.start(parse_action(discovery_action(store._manifest["fixture_case"], step)), policy(),
                       session_id=store._manifest["session_id"], session_step=step, backend=backend)


def finish(store, step):
    raw = result(store, step)
    store.finish(start(store, step), raw, execution_status=raw["status"])
    return _observation(step + 1, {"execution_status": raw["status"], "untrusted_result": raw})


def summary(store, *, steps=3, succeeded=3, mode="execute", stop="coordinator_done"):
    return {"session_id": store._manifest["session_id"], "steps_attempted": steps,
            "actions_succeeded": succeeded, "output_reserved_bytes": steps * 1024,
            "mode": mode, "stop_reason": stop,
            "session_status": "completed" if stop == "coordinator_done" else "stopped"}


def receipt(store):
    return {**(store._lab_context or {"identity": store._manifest["owned_lab"],
                                     "connection_count": 0, "request_count": 0}), "status": "closed"}


def complete(path, *, case="a"):
    with store_at(path, case=case) as store:
        observation = _observation(1, None)
        for step in (1, 2, 3):
            if store.record_decision(step, observation).action is None:
                break
            observation = finish(store, step)
        store.record_lab_closed(receipt(store))
        return store.finalize(summary(store, succeeded=2 if case in {"d", "e", "f"} else 3,
                                      stop={"d": "action_timeout", "e": "action_output_limit"}.get(case, "coordinator_done")))


def rows(path):
    return [json.loads(line) for line in (path / "evidence.jsonl").read_text().splitlines()]


def write_rows(path, events):
    (path / "evidence.jsonl").write_text("\n".join(json.dumps(event) for event in events) + "\n")


def snapshot(path):
    return {item.name: (item.read_bytes(), item.stat().st_mtime_ns) for item in path.iterdir()}


def test_deterministic_spec_and_fresh_instances_bind_the_same_seed():
    left, right = (contract.identity("a", str(uuid4())) for _ in range(2))
    assert left["spec_sha256"] == right["spec_sha256"] and left["instance_id"] != right["instance_id"]
    assert left["spec_sha256"] != contract.identity("b", str(uuid4()))["spec_sha256"]
    assert contract.spec("a")["topology"] == [{"service_id": "assessment-http", "target": "127.0.0.1",
                                               "port": 8080, "protocol": "http-over-tcp"}]
    copy_of_identity = contract.validate_identity(left, case="a")
    copy_of_identity["scenario"] = "b"
    assert left["scenario"] == "a"


@pytest.mark.parametrize("fault", ["scenario", "digest", "uuid", "version", "extra", "type", "wrong_case"])
def test_identity_rejects_mixed_specs_unknown_fields_and_instances(fault):
    value = contract.identity("a", str(uuid4()))
    if fault == "scenario":
        value["scenario"] = "b"
    elif fault == "digest":
        value["spec_sha256"] = "0" * 64
    elif fault == "uuid":
        value["instance_id"] = "not-an-instance"
    elif fault == "version":
        value["version"] = "2"
    elif fault == "extra":
        value["attach"] = "/proc/123/ns/net"
    elif fault == "type":
        value = []
    with pytest.raises(ValueError):
        contract.validate_identity(value, case="b" if fault == "wrong_case" else "a")


def test_old_card_digest_is_stable_and_lab_profile_preserves_exact_actions():
    assert workflow.card_digest() == "0ee868de914e71e0ad266c2500eb5657e82ffe498a0e7a7da8c2f5c8d36312b9"
    assert workflow.card_identity(owned_lab=True)["version"] == "2"
    assert workflow.card(owned_lab=True)["action_digests"] == workflow.card()["action_digests"]
    assert workflow.card_digest(owned_lab=True) != workflow.card_digest()
    assert workflow.decide("a", 1, [], _observation(1, None), owned_lab=True).to_dict()["workflow_version"] == "2"


@pytest.mark.parametrize("case,outcome", [("a", "validated"), ("b", "not_demonstrated"),
                                         ("c", "inconclusive"), ("d", "inconclusive"),
                                         ("e", "inconclusive"), ("f", "inconclusive")])
def test_every_lab_case_has_independent_read_only_replay(tmp_path, case, outcome):
    path = tmp_path / "lab"
    report = complete(path, case=case)
    assert report["workflow"] == evidence.OWNED_LAB_WORKFLOW
    assert report["workflow_card"] == workflow.card_identity(owned_lab=True)
    assert report["outcome"] == outcome and report["integrity_issues"] == []
    assert report["owned_lab"]["closure"]["identity"] == report["owned_lab"]["identity"]
    assert report["owned_lab"]["closure"]["status"] == "closed"
    assert len(rows(path)) <= 12
    for index, record in enumerate(report["records"], start=1):
        artifact = json.loads((path / record["artifact"]["filename"]).read_bytes())
        assert artifact["owned_lab"] == {"identity": report["owned_lab"]["identity"],
                                          "connection_count": index, "request_count": index - 1}
        assert record["backend"] == contract.BACKEND
    before = snapshot(path)
    assert inspect_assessment(path) == report and snapshot(path) == before


def test_legacy_parser_does_not_accept_persistent_context_without_evidence_validation(tmp_path):
    with store_at(tmp_path / "lab") as store:
        raw = result(store, 1)
        assert parse_observation(discovery_action("a", 1), raw, execution_status="succeeded")["classification"] == "inconclusive"


@pytest.mark.parametrize("fault", ["missing", "changed_instance", "changed_backend", "no_connection",
                                   "extra_connection", "tcp_request", "bool_counter"])
def test_invalid_result_context_poison_store_before_artifact_publication(tmp_path, fault):
    path = tmp_path / "lab"
    with store_at(path) as store:
        store.record_decision(1, _observation(1, None))
        execution = start(store, 1)
        raw = result(store, 1)
        if fault == "missing":
            raw.pop("owned_lab")
        elif fault == "changed_instance":
            raw["owned_lab"]["identity"]["instance_id"] = str(uuid4())
        elif fault == "changed_backend":
            raw["backend"] = "linux-authorized-discovery-fixture-executor-v1"
        else:
            key, value = {"no_connection": ("connection_count", 0), "extra_connection": ("connection_count", 2),
                          "tcp_request": ("request_count", 1), "bool_counter": ("connection_count", True)}[fault]
            raw["owned_lab"][key] = value
        with pytest.raises(EvidenceUnavailable):
            store.finish(execution, raw, execution_status="succeeded")
        with pytest.raises(EvidenceUnavailable):
            store.record_lab_closed(receipt(store))
    assert not list(path.glob("result-*.json"))
    report = inspect_assessment(path)
    assert report["outcome"] == "inconclusive"
    assert {"execution_completion_unknown", "owned_lab_closure_missing"} <= set(report["integrity_issues"])


@pytest.mark.parametrize("fault", ["missing_closure", "wrong_instance", "wrong_count", "reordered", "duplicate"])
def test_teardown_integrity_is_required_for_a_positive_report(tmp_path, fault):
    path = tmp_path / "lab"
    complete(path)
    events = rows(path)
    close_index = next(index for index, row in enumerate(events) if row["event_type"] == "assessment_owned_lab_closed")
    if fault == "missing_closure":
        del events[close_index]
    elif fault == "wrong_instance":
        events[close_index]["receipt"]["identity"]["instance_id"] = str(uuid4())
    elif fault == "wrong_count":
        events[close_index]["receipt"]["connection_count"] = 4
    elif fault == "reordered":
        events[0], events[close_index] = events[close_index], events[0]
    else:
        events.insert(close_index, copy.deepcopy(events[close_index]))
    write_rows(path, events)
    before = snapshot(path)
    report = inspect_assessment(path)
    assert report["outcome"] == "inconclusive" and report["integrity_issues"]
    assert snapshot(path) == before


@pytest.mark.parametrize("fault", ["instance", "counters", "missing", "backend"])
def test_rehashed_artifact_with_invalid_continuity_is_rejected_on_inspection(tmp_path, fault):
    path = tmp_path / "lab"
    complete(path)
    events = rows(path)
    finished = [event for event in events if event["event_type"] == "assessment_execution_finished"][1]
    record = finished["record"]
    artifact = path / record["artifact"]["filename"]
    raw = json.loads(artifact.read_bytes())
    if fault == "instance":
        raw["owned_lab"]["identity"]["instance_id"] = str(uuid4())
    elif fault == "counters":
        raw["owned_lab"].update(connection_count=1, request_count=1)
    elif fault == "missing":
        raw.pop("owned_lab")
    else:
        raw["backend"] = "linux-authorized-discovery-fixture-executor-v1"
    encoded = evidence._encode(raw)
    artifact.write_bytes(encoded)
    record["artifact"].update(sha256=hashlib.sha256(encoded).hexdigest(), bytes=len(encoded))
    record["authority_observation_sha256"] = evidence._observation_digest(2, "succeeded", raw)
    write_rows(path, events)
    report = inspect_assessment(path)
    assert report["outcome"] == "inconclusive" and "journal_or_artifact_incomplete" in report["integrity_issues"]


def test_missing_teardown_prevents_finalization_and_crash_inspection_is_read_only(tmp_path):
    path = tmp_path / "lab"
    with store_at(path) as store:
        observation = _observation(1, None)
        for step in (1, 2, 3):
            store.record_decision(step, observation)
            observation = finish(store, step)
        with pytest.raises(EvidenceUnavailable):
            store.finalize(summary(store))
    before = snapshot(path)
    report = inspect_assessment(path)
    assert report["outcome"] == "inconclusive" and "owned_lab_closure_missing" in report["integrity_issues"]
    assert snapshot(path) == before and not (path / "report.json").exists()


@pytest.mark.parametrize("status", ["cancelled", "blocked", "failed", "timeout"])
def test_controller_failure_without_runtime_context_remains_incomplete(tmp_path, status):
    path = tmp_path / "lab"
    with store_at(path) as store:
        store.record_decision(1, _observation(1, None))
        execution = start(store, 1)
        # Controller intentionally cannot fabricate service identity/counters
        # when execution is interrupted before an attributable reply arrives.
        with pytest.raises(EvidenceUnavailable):
            store.finish(execution, {"status": status}, execution_status=status)
    before = snapshot(path)
    report = inspect_assessment(path)
    assert report["outcome"] == "inconclusive" and report["owned_lab"]["closure"] is None
    assert {"execution_completion_unknown", "owned_lab_closure_missing"} <= set(report["integrity_issues"])
    assert len(report["records"]) == 1 and report["records"][0]["artifact"] is None
    assert not list(path.glob("result-*.json")) and snapshot(path) == before


def test_no_execution_closure_and_dry_run_do_not_claim_service_started(tmp_path):
    path = tmp_path / "lab"
    with store_at(path) as store:
        store.record_decision(1, _observation(1, None))
        store.record_decision(2, _observation(2, {"execution_status": "dry_run"}))
        store.record_lab_closed(receipt(store))
        report = store.finalize(summary(store, steps=2, succeeded=0, mode="dry_run"))
    assert report["owned_lab"]["closure"]["connection_count"] == 0
    assert report["records"] == [] and report["outcome"] == "inconclusive"
    assert inspect_assessment(path) == report
