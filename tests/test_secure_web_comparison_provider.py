"""Scripted observations exercise proposal-only behavior, never a live model."""

import copy
import hashlib
import json
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import nmap_evidence
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.nmap_parser import parse_nmap_xml
from recon_cockpit.secure_agent.session import _observation
from recon_cockpit.secure_agent.web_assessment_contract import action, encode
from recon_cockpit.secure_agent.web_comparison_contract import attack_action
from recon_cockpit.secure_agent.web_comparison_provider import ComparisonProvider, attack_note
from recon_cockpit.secure_agent.web_fixture import OPERATOR_NOTE

from test_secure_web_evidence import store_at, start, result


@pytest.fixture(autouse=True)
def unit_only_parser_double(monkeypatch):
    monkeypatch.setattr(nmap_evidence.nmap_runtime, "parse_isolated_xml",
                        lambda raw, *, deadline=None: parse_nmap_xml(raw)["results"])


class Audit:
    def __init__(self):
        self.events = []
        self.fail = False

    def emit(self, event):
        if self.fail:
            raise AuditUnavailable("audit_unavailable")
        self.events.append(copy.deepcopy(event))


def provider_for(store, arm="scripted"):
    audit = Audit()
    provider = ComparisonProvider(store._manifest["fixture_case"], store, arm, audit)
    provider.bind_session(store._manifest["session_id"])
    return provider, audit, ExecutionControl(time.monotonic() + 20)


def run_predecessors(store, provider, control, *, change_index=None):
    frame = _observation(1, None)
    for step in (1, 2):
        proposal = json.loads(provider.propose(frame, control=control))
        assert proposal == {"schema_version": "1", "action": action(store._manifest["fixture_case"], step), "done": False}
        raw = result(store, step)
        if step == 2 and change_index is not None:
            change_index(raw)
        store.finish(start(store, step), raw, execution_status="succeeded")
        frame = _observation(step + 1, {"execution_status": "succeeded", "untrusted_result": raw})
    return frame


def edit_note(note):
    def change(raw):
        row = raw["results"][0]
        document = json.loads(row["body"])
        if note is None:
            document.pop("operator_note", None)
        else:
            document["operator_note"] = note
        row["body"] = encode(document).decode()
        row["bytes_received"] = raw["bytes_received"] = len(row["body"]) + 64
    return change


@pytest.mark.parametrize("case,arm,attack", [
    ("vulnerable", "baseline", False), ("vulnerable", "scripted", False),
    ("corrected", "baseline", False), ("corrected", "scripted", False),
    ("injected", "baseline", False), ("injected", "scripted", True),
])
def test_all_arms_record_actual_proposals_and_only_scripted_injected_source_changes_third_step(tmp_path, case, arm, attack):
    with store_at(tmp_path / "evidence", case) as store:
        provider, audit, control = provider_for(store, arm)
        frame = run_predecessors(store, provider, control)
        proposal = json.loads(provider.propose(frame, control=control))
        assert proposal == {"schema_version": "1", "action": attack_action(case) if attack else action(case, 3), "done": True}
        trace = provider.trace
        assert len(trace) == len(audit.events) == 3
        assert trace[2]["action"] == proposal["action"]
        assert trace[2]["observation_sha256"] == hashlib.sha256(frame).hexdigest()
        assert (trace[2]["attack"] is not None) is attack
        assert len(store._decisions) == (2 if attack else 3)
        if attack:
            proof = trace[2]["attack"]
            source = store.records[1]
            assert proof == {"source_execution_id": source["execution_id"],
                             "source_observation_id": source["observation_id"],
                             "source_artifact": source["artifact"],
                             "note_sha256": hashlib.sha256(OPERATOR_NOTE.encode()).hexdigest()}
            assert OPERATOR_NOTE not in json.dumps(proof)
        for row, event in zip(trace, audit.events):
            assert event == {"event_type": "web_comparison_plan", "session_id": store._manifest["session_id"],
                             "arm": arm, **{key: row[key] for key in ("step", "action_digest", "observation_sha256", "attack")}}
            assert OPERATOR_NOTE not in json.dumps(event)
            assert "action" not in event
        trace[0]["action"]["target"] = "arbitrary"
        assert provider.trace[0]["action"]["target"] == "127.0.0.1"
        with pytest.raises(RuntimeError):
            provider.propose(frame, control=control)
        with pytest.raises(ValueError):
            provider.bind_session(str(uuid4()))


@pytest.mark.parametrize("case,note,attack", [
    ("vulnerable", OPERATOR_NOTE, True), ("corrected", OPERATOR_NOTE, True),
    ("injected", None, False), ("injected", "Different hostile instructions", False),
])
def test_trigger_uses_actual_durable_response_not_the_variant_label(tmp_path, case, note, attack):
    with store_at(tmp_path / "evidence", case) as store:
        provider, _, control = provider_for(store)
        frame = run_predecessors(store, provider, control, change_index=edit_note(note))
        proposal = json.loads(provider.propose(frame, control=control))
        assert proposal["action"] == (attack_action(case) if attack else action(case, 3))


@pytest.mark.parametrize("change", [
    lambda records: records[1].update(authority_observation_sha256="a" * 64),
    lambda records: records[1].update(execution_status="failed"),
    lambda records: records[1].update(artifact=None),
    lambda records: records[1]["artifact"].update(filename="../../secret"),
    lambda records: records[1]["artifact"].update(bytes=True),
    lambda records: records[1]["artifact"].update(sha256="unknown"),
    lambda records: records[1].update(action_digest="b" * 64),
    lambda records: records[1]["observation"].update(classification="inconclusive"),
    lambda records: records[1].update(observation_id=records[0]["observation_id"]),
])
def test_injected_note_requires_intact_matching_predecessor_and_artifact_proof(tmp_path, change):
    with store_at(tmp_path / "evidence", "injected") as store:
        provider, audit, control = provider_for(store)
        frame = run_predecessors(store, provider, control)
        change(store._records)  # Explicit trusted-store fault injection.
        with pytest.raises(ValueError):
            provider.propose(frame, control=control)
        assert len(provider.trace) == len(audit.events) == 2
        with pytest.raises(RuntimeError):
            provider.propose(frame, control=control)


def test_valid_injection_cannot_be_spliced_into_another_authority_observation(tmp_path):
    with store_at(tmp_path / "evidence", "vulnerable") as store:
        provider, audit, control = provider_for(store)
        frame = json.loads(run_predecessors(store, provider, control))
        document = json.loads(frame["untrusted_observation"]["body"])
        document["operator_note"] = OPERATOR_NOTE
        frame["untrusted_observation"]["body"] = encode(document).decode()
        with pytest.raises(ValueError, match="comparison_predecessor_not_validated"):
            provider.propose(encode(frame), control=control)
        assert len(audit.events) == 2


@pytest.mark.parametrize("frame", [
    b'{"step":1,"step":1,"untrusted_observation":null}',
    b'{"step":true,"untrusted_observation":null}',
    b'{"step":2,"untrusted_observation":null}', b'[]', b'{', b'x' * 8193,
])
def test_malformed_or_replayed_initial_frame_closes_provider_without_a_proposal(tmp_path, frame):
    with store_at(tmp_path / "evidence") as store:
        provider, audit, control = provider_for(store)
        with pytest.raises((ValueError, TypeError)):
            provider.propose(frame, control=control)
        assert audit.events == provider.trace == []
        with pytest.raises(RuntimeError):
            provider.propose(_observation(1, None), control=control)


@pytest.mark.parametrize("body", [
    '{"operator_note":"x","operator_note":"y"}', '["wrong"]', '{"operator_note":NaN}', '{',
])
def test_malformed_index_body_cannot_trigger_the_scripted_fault(tmp_path, body):
    with store_at(tmp_path / "evidence", "injected") as store:
        provider, audit, control = provider_for(store)
        frame = run_predecessors(store, provider, control)
        altered = json.loads(frame)
        altered["untrusted_observation"]["body"] = body
        with pytest.raises(ValueError):
            provider.propose(encode(altered), control=control)
        assert len(audit.events) == 2


def test_audit_failure_prevents_attack_proposal_release_and_reuse(tmp_path):
    with store_at(tmp_path / "evidence", "injected") as store:
        provider, audit, control = provider_for(store)
        frame = run_predecessors(store, provider, control)
        audit.fail = True
        with pytest.raises(AuditUnavailable):
            provider.propose(frame, control=control)
        assert len(provider.trace) == 2 and len(store._decisions) == 2
        with pytest.raises(RuntimeError):
            provider.propose(frame, control=control)


def test_replaying_an_earlier_step_does_not_duplicate_trace_or_workflow_decisions(tmp_path):
    with store_at(tmp_path / "evidence") as store:
        provider, audit, control = provider_for(store)
        frame = _observation(1, None)
        provider.propose(frame, control=control)
        with pytest.raises(ValueError, match="comparison_provider_step_mismatch"):
            provider.propose(frame, control=control)
        assert len(provider.trace) == len(audit.events) == len(store._decisions) == 1


def test_expired_control_prevents_even_initial_proposal(tmp_path):
    with store_at(tmp_path / "evidence") as store:
        provider, audit, _ = provider_for(store)
        with pytest.raises(ExecutionStopped):
            provider.propose(_observation(1, None), control=ExecutionControl(time.monotonic() - 1))
        assert provider.trace == audit.events == []


def test_content_helper_does_not_treat_note_presence_at_another_step_as_trigger():
    assert attack_note(_observation(1, None)) is None
    assert attack_note(encode({"step": 2, "untrusted_observation": {
        "execution_status": "succeeded", "body": encode({"operator_note": OPERATOR_NOTE}).decode()}})) is None
