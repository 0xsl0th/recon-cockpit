"""Durable workflow decisions, artifact replay and fail-closed crash inspection."""

import json
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import evidence, workflow
from recon_cockpit.secure_agent.discovery_contract import discovery_action
from recon_cockpit.secure_agent.evidence import EvidenceStore, EvidenceUnavailable, inspect_assessment
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session import _observation
from recon_cockpit.secure_agent.worker import _response


def policy():
    return parse_policy({
        "schema_version": "1", "policy_version": "workflow-evidence-tests-v1",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": ["tcp_connect", "http_probe"],
        "allowed_ports": [8080], "allowed_methods": ["GET"],
        "max_timeout_seconds": 3, "max_output_bytes": 1024, "max_targets": 1,
        "require_approval": False, "approval_ttl_seconds": 5,
    })


def store_at(path, *, case="a"):
    return EvidenceStore(path, session_id=str(uuid4()), policy=policy(), case=case,
                         discovery=True, workflow=True)


def result(case, step):
    if step == 1:
        return {"status": "succeeded", "bytes_received": 0, "truncated": False,
                "results": [{"target": "127.0.0.1", "port": 8080, "state": "open"}]}
    if step == 3 and case in {"d", "e"}:
        return {"status": "timeout" if case == "d" else "output_limit", "bytes_received": 0,
                "truncated": False, "results": []}
    status, body, _headers = _response(discovery_action(case, step)["parameters"]["path"])
    return {"status": "succeeded", "bytes_received": len(body) + 64, "truncated": False,
            "results": [{"target": "127.0.0.1", "port": 8080, "http_status": status,
                         "body": body.decode("utf-8"), "bytes_received": len(body) + 64,
                         "truncated": False, "response_sha256": "a" * 64}]}


def start(store, step, *, case="a", action=None):
    return store.start(parse_action(action or discovery_action(case, step)), policy(),
                       session_id=store._manifest["session_id"], session_step=step,
                       backend="linux-authorized-discovery-fixture-executor-v1")


def finish(store, step, *, case="a", raw=None):
    raw = result(case, step) if raw is None else raw
    store.finish(start(store, step, case=case), raw, execution_status=raw["status"])
    return _observation(step + 1, {"execution_status": raw["status"], "untrusted_result": raw})


def summary(store, *, steps=3, succeeded=3, mode="execute", stop="coordinator_done"):
    return {"session_id": store._manifest["session_id"],
            "session_status": "completed" if stop == "coordinator_done" else "stopped",
            "stop_reason": stop, "steps_attempted": steps, "actions_succeeded": succeeded,
            "output_reserved_bytes": steps * 1024, "mode": mode}


def complete(path, *, case="a"):
    with store_at(path, case=case) as store:
        observation = _observation(1, None)
        for step in (1, 2, 3):
            decision = store.record_decision(step, observation)
            if decision.action is None:
                break
            observation = finish(store, step, case=case)
        stop = {"d": "action_timeout", "e": "action_output_limit"}.get(case, "coordinator_done")
        return store.finalize(summary(store, succeeded=2 if case in {"d", "e", "f"} else 3, stop=stop))


def rows(path):
    return [json.loads(line) for line in (path / "evidence.jsonl").read_text().splitlines()]


def write_rows(path, values):
    (path / "evidence.jsonl").write_text("\n".join(json.dumps(value) for value in values) + "\n")


@pytest.mark.parametrize("reason", workflow.BLOCKED_REASONS)
def test_blocked_authority_reason_is_bounded_persisted_and_replayed(tmp_path, reason):
    path = tmp_path / "workflow"
    with store_at(path) as store:
        store.record_decision(1, _observation(1, None))
        closed = summary(store, steps=1, succeeded=0, stop="action_blocked")
        closed["steps"] = [{"step": 1, "execution_status": "blocked", "reasons": [reason]}]
        report = store.finalize(closed)
    assert report["execution"]["blocked_reason"] == report["terminal_decision"]["reason"] == reason
    assert report["outcome"] == "inconclusive" and report["records"] == []
    assert "steps" not in report["execution"]
    assert inspect_assessment(path) == report


@pytest.mark.parametrize("last", [
    {"step": 1, "execution_status": "blocked", "reasons": ["PRIVATE CALLBACK TEXT"]},
    {"step": 1, "execution_status": "blocked", "reasons": ["approval_missing", "PRIVATE TEXT"]},
    {"step": 2, "execution_status": "blocked", "reasons": ["approval_missing"]},
    {"step": True, "execution_status": "blocked", "reasons": ["approval_missing"]},
    {"step": 1, "execution_status": "succeeded", "reasons": ["approval_missing"]},
])
def test_untrusted_or_mismatched_step_text_is_not_a_terminal_explanation(tmp_path, last):
    path = tmp_path / "workflow"
    with store_at(path) as store:
        store.record_decision(1, _observation(1, None))
        closed = summary(store, steps=1, succeeded=0, stop="action_blocked")
        closed["steps"] = [last]
        report = store.finalize(closed)
    assert report["execution"]["blocked_reason"] is None
    assert report["terminal_decision"]["reason"] == "action_blocked"
    assert all(b"PRIVATE" not in item.read_bytes() for item in path.iterdir())
    assert inspect_assessment(path) == report


@pytest.mark.parametrize("reason", ["PRIVATE TEXT", {"approval_missing": True}, True, ["approval_missing"]])
def test_inspector_rejects_invalid_persisted_blocked_reason(tmp_path, reason):
    path = tmp_path / "workflow"
    with store_at(path) as store:
        store.record_decision(1, _observation(1, None))
        store.finalize(summary(store, steps=1, succeeded=0, stop="action_blocked"))
    events = rows(path)
    for event in events:
        if "summary" in event:
            event["summary"]["blocked_reason"] = reason
    write_rows(path, events)
    report = inspect_assessment(path)
    assert report["outcome"] == "inconclusive"
    assert "journal_or_artifact_incomplete" in report["integrity_issues"]
    assert report["terminal_decision"] is None


def test_blocked_reason_cannot_be_attached_to_successful_closure(tmp_path):
    path = tmp_path / "workflow"
    complete(path)
    events = rows(path)
    for event in events:
        if "summary" in event:
            event["summary"]["blocked_reason"] = "approval_missing"
    write_rows(path, events)
    report = inspect_assessment(path)
    assert report["outcome"] == "inconclusive" and report["integrity_issues"]


@pytest.mark.parametrize("case,outcome", [("a", "validated"), ("b", "not_demonstrated"),
                                         ("c", "inconclusive"), ("d", "inconclusive"),
                                         ("e", "inconclusive"), ("f", "inconclusive")])
def test_versioned_report_replays_every_case_with_evidence_backed_decisions(tmp_path, case, outcome):
    path = tmp_path / "workflow"
    report = complete(path, case=case)
    assert report["workflow"] == evidence.VERSIONED_WORKFLOW
    assert report["workflow_card"] == workflow.card_identity()
    assert report["outcome"] == outcome and report["integrity_issues"] == []
    assert len(report["decision_trace"]) == 3
    assert report["terminal_decision"]["step"] == 4
    assert len({row["decision_id"] for row in report["decision_trace"]}
               | {report["terminal_decision"]["decision_id"]}) == 4
    for decision in report["decision_trace"]:
        assert decision["predecessors"] == [
            {"execution_id": record["execution_id"], "observation_id": record["observation_id"]}
            for record in report["records"][:decision["step"] - 1]]
    if case == "f":
        assert report["decision_trace"][-1]["decision_kind"] == "stop"
        assert report["decision_trace"][-1]["execution_status"] == "not_proposed"
        assert len(report["records"]) == 2
    else:
        assert [row["execution_id"] for row in report["decision_trace"]] == [
            row["execution_id"] for row in report["records"]]
    assert len(rows(path)) <= 11
    assert (path / "evidence.jsonl").stat().st_size <= evidence.MAX_JOURNAL_BYTES
    assert (path / "report.json").stat().st_size <= evidence.MAX_REPORT_BYTES
    assert inspect_assessment(path) == report


def test_dry_run_proposal_needs_missing_evidence_stop_and_has_no_execution(tmp_path):
    path = tmp_path / "workflow"
    with store_at(path) as store:
        first = store.record_decision(1, _observation(1, None))
        assert first.action is not None
        second = store.record_decision(2, _observation(2, {"execution_status": "dry_run"}))
        assert second.action is None and second.reason == "predecessor_evidence_missing"
        report = store.finalize(summary(store, steps=2, succeeded=0, mode="dry_run"))
    assert report["records"] == [] and report["outcome"] == "inconclusive"
    assert [row["execution_status"] for row in report["decision_trace"]] == ["not_executed", "not_proposed"]
    assert report["terminal_decision"]["reason"] == "dry_run_has_no_execution_evidence"
    assert inspect_assessment(path) == report


@pytest.mark.parametrize("stop", ["proposal_denied", "action_blocked", "output_limit", "step_limit",
                                   "session_cancelled", "session_timeout", "provider_failed"])
def test_unexecuted_proposal_and_actual_authority_stop_remain_distinct(tmp_path, stop):
    path = tmp_path / "workflow"
    with store_at(path) as store:
        store.record_decision(1, _observation(1, None))
        report = store.finalize(summary(store, steps=1, succeeded=0, stop=stop))
    assert report["outcome"] == "inconclusive"
    assert report["terminal_decision"]["reason"] == stop
    assert report["decision_trace"][0]["execution_status"] == "not_executed"
    assert report["decision_trace"][0]["execution_id"] is None
    assert inspect_assessment(path) == report


@pytest.mark.parametrize("fault", ["missing", "replayed", "out_of_order", "wrong_digest", "stop_then_start"])
def test_launch_requires_current_durable_proposal_and_failures_latch(tmp_path, fault):
    with store_at(tmp_path / "workflow") as store:
        if fault != "missing":
            store.record_decision(1, _observation(1, None))
        with pytest.raises(EvidenceUnavailable):
            if fault == "replayed":
                store.record_decision(1, _observation(1, None))
            elif fault == "out_of_order":
                store.record_decision(3, _observation(3, {"execution_status": "dry_run"}))
            elif fault == "wrong_digest":
                action = discovery_action("a", 1)
                action["rationale"] = "Changed planner rationale"
                start(store, 1, action=action)
            elif fault == "stop_then_start":
                store.record_decision(2, _observation(2, {"execution_status": "dry_run"}))
                start(store, 1)
            else:
                start(store, 1)
        with pytest.raises(EvidenceUnavailable):
            store.record_decision(1, _observation(1, None))
        assert store.records == []


@pytest.mark.parametrize("fault", ["decision", "terminal", "closure"])
def test_failed_decision_writes_latch_and_never_publish_a_finding(tmp_path, monkeypatch, fault):
    path = tmp_path / "workflow"
    with store_at(path) as store:
        original = store._emit
        failing_event = {"decision": "assessment_workflow_decision", "terminal": "assessment_workflow_terminal",
                         "closure": "assessment_finished"}[fault]

        def emit(value):
            if value["event_type"] == failing_event:
                raise OSError("PRIVATE-ERROR-MARKER")
            return original(value)

        monkeypatch.setattr(store, "_emit", emit)
        with pytest.raises(EvidenceUnavailable, match="^evidence_unavailable$"):
            store.record_decision(1, _observation(1, None))
            store.finalize(summary(store, steps=1, succeeded=0, stop="proposal_denied"))
        with pytest.raises(EvidenceUnavailable):
            start(store, 1)
    report = inspect_assessment(path)
    assert report["outcome"] == "inconclusive"
    assert "assessment_closure_missing" in report["integrity_issues"]
    assert "PRIVATE-ERROR-MARKER" not in json.dumps(report)
    assert not (path / "report.json").exists()


@pytest.mark.parametrize("fault", ["missing_decision", "changed_reason", "changed_digest", "changed_predecessor",
                                   "replayed_decision", "out_of_order", "missing_terminal", "missing_closure",
                                   "terminal_changed", "summary_disagrees", "partial_tail", "action_identity"])
def test_inspector_recomputes_decisions_and_rejects_corruption_without_writes(tmp_path, fault):
    path = tmp_path / "workflow"
    complete(path)
    values = rows(path)
    if fault == "missing_decision":
        del values[3]
    elif fault == "changed_reason":
        values[3]["decision"]["reason"] = "initial_scoped_discovery"
    elif fault == "changed_digest":
        values[3]["decision"]["action_digest"] = "b" * 64
    elif fault == "changed_predecessor":
        values[3]["decision"]["predecessors"][0]["observation_id"] = str(uuid4())
    elif fault == "replayed_decision":
        values[3]["decision"]["decision_id"] = values[0]["decision"]["decision_id"]
    elif fault == "out_of_order":
        values[3], values[4] = values[4], values[3]
    elif fault == "missing_terminal":
        del values[-2]
    elif fault == "missing_closure":
        del values[-1]
    elif fault == "terminal_changed":
        values[-2]["decision"]["reason"] = "diagnostic_endpoint_not_found"
    elif fault == "summary_disagrees":
        values[-1]["summary"]["stop_reason"] = "step_limit"
    elif fault == "action_identity":
        identity = str(uuid4())
        values[1]["record"]["action"]["action_id"] = identity
        values[2]["record"]["action"]["action_id"] = identity
    write_rows(path, values)
    if fault == "partial_tail":
        journal = path / "evidence.jsonl"
        journal.write_bytes(journal.read_bytes()[:-12])
    before = {item.name: item.read_bytes() for item in path.iterdir()}
    report = inspect_assessment(path)
    assert report["outcome"] == "inconclusive" and report["integrity_issues"]
    assert {item.name: item.read_bytes() for item in path.iterdir()} == before


@pytest.mark.parametrize("field,value", [("id", "other-card"), ("version", "2"), ("sha256", "a" * 64)])
def test_unknown_card_identity_is_rejected(tmp_path, field, value):
    path = tmp_path / "workflow"
    complete(path)
    manifest = json.loads((path / "manifest.json").read_text())
    manifest["workflow_card"][field] = value
    (path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(EvidenceUnavailable):
        inspect_assessment(path)


def test_duplicate_observation_identity_is_rejected_before_terminal_interpretation(tmp_path):
    path = tmp_path / "workflow"
    complete(path)
    values = rows(path)
    values[8]["record"]["observation_id"] = values[2]["record"]["observation_id"]
    # Even a rewritten terminal must not make duplicate observation IDs into
    # valid independent observations when the parser classifications agree.
    records = [values[index]["record"] for index in (2, 5, 8)]
    values[9]["decision"].update(workflow.terminal_decision("a", records, values[9]["summary"]).to_dict())
    write_rows(path, values)
    inspected = inspect_assessment(path)
    assert inspected["outcome"] == "inconclusive"
    assert "journal_or_artifact_incomplete" in inspected["integrity_issues"]
    assert len(inspected["finding"]["evidence"]) == 2


def test_crash_after_proposal_or_launch_preserves_only_durable_state(tmp_path):
    for launch in (False, True):
        path = tmp_path / str(launch)
        with store_at(path) as store:
            store.record_decision(1, _observation(1, None))
            if launch:
                start(store, 1)
        before = {item.name: item.read_bytes() for item in path.iterdir()}
        report = inspect_assessment(path)
        assert report["outcome"] == "inconclusive"
        assert {"assessment_closure_missing", "workflow_terminal_missing"} <= set(report["integrity_issues"])
        assert report["decision_trace"][0]["execution_status"] == ("completion_unknown" if launch else "not_executed")
        assert {item.name: item.read_bytes() for item in path.iterdir()} == before
        with pytest.raises(EvidenceUnavailable):
            store_at(path)


def test_hostile_body_is_private_and_cannot_choose_another_transition(tmp_path):
    path = tmp_path / "workflow"
    hostile = "<script>PRIVATE-HOSTILE-MARKER</script> https://example.invalid/steal"
    with store_at(path) as store:
        store.record_decision(1, _observation(1, None))
        observation = finish(store, 1)
        store.record_decision(2, observation)
        raw = result("a", 2)
        raw["results"][0]["body"] = hostile
        observation = finish(store, 2, raw=raw)
        decision = store.record_decision(3, observation)
        assert decision.action is None and decision.reason == "fixture_index_not_established"
        report = store.finalize(summary(store, succeeded=2))
    assert inspect_assessment(path) == report
    safe = "".join((path / name).read_text() for name in ("evidence.jsonl", "report.json", "report.md"))
    assert hostile not in safe and "PRIVATE-HOSTILE-MARKER" not in safe
    assert '"body"' not in safe and '"rationale"' not in safe
    assert report["outcome"] == "inconclusive"


@pytest.mark.parametrize("discovery,selector", [(False, True), (True, "yes"), (True, 1)])
def test_workflow_selector_requires_explicit_discovery_boolean(tmp_path, discovery, selector):
    with pytest.raises(EvidenceUnavailable):
        EvidenceStore(tmp_path / "workflow", session_id=str(uuid4()), policy=policy(), case="a",
                      discovery=discovery, workflow=selector)
