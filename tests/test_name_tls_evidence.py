"""Saved authority/audit consistency; synthetic receipts are not native proof."""

from copy import deepcopy
import json
import os
import time
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import name_tls_contract as contract, name_tls_evidence as evidence
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.evidence import EvidenceUnavailable
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.name_tls_probes import run_probe_cases
from test_name_tls_native_runtime import prepared, bundle

SESSION = str(UUID(int=11001))


def manifest(configuration="A", case="O1", *, execute=False, approval=False):
    selected = contract.selection(configuration, case)
    runtime = bundle(prepared(configuration, case))
    return {"schema_version": "1", "assessment_id": str(UUID(int=11002)), "session_id": SESSION,
            "selection": selected, "slots": list(contract.operation_plan(selected) + contract.attempt_slots(selected)),
            "policy": contract.policy_for_selection(selected, require_approval=approval).to_dict(),
            "limits": contract.limits(selected), "runtime": runtime,
            "identity": contract.identity(selected, SESSION, runtime, owner_id=str(UUID(int=11003))),
            "execute": execute, "unattended_owned_lab_test": not approval}


def closure(chosen):
    return {"identity": chosen["identity"], "status": "closed", "launcher_cleanup_verified": True,
            "counters_source": "last_acknowledged_result", "last_result": None}


def save(directory, chosen):
    policy = contract.validate_policy(chosen["policy"], chosen["selection"])
    class Backend:
        name = contract.BACKEND
        def check_available(self, action=None):
            pass
        def run(self, action, policy):
            return {"status": "failed"}
    with evidence.NameTLSEvidenceStore(directory, chosen) as store:
        with AuditSink(directory / "audit.jsonl") as audit:
            controller = Controller(policy, audit, Backend(), session_id=SESSION, evidence=store)
            outcomes = []
            if chosen["slots"]:
                action = contract.dns_action(chosen["selection"], chosen["identity"])
                outcomes.append(controller.submit(action, execute=chosen["execute"], session_step=1))
        return store.finalize(outcomes, closure=closure(chosen), elapsed_ms=10)


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("execute,approval", ((False, False), (True, False), (True, True)))
def test_private_saved_report_replay_is_immutable_and_never_turns_failure_into_useful(tmp_path, configuration, execute, approval):
    directory = tmp_path / "evidence"
    report = save(directory, manifest(configuration, execute=execute, approval=approval))
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    assert evidence.inspect_trial(directory) == report
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before
    assert report["useful_task_completed"] is False
    assert report["case_passed"] is bool(execute and approval)
    assert stat_mode(directory) == 0o700
    assert all(stat_mode(path) == 0o600 for path in directory.iterdir())


def stat_mode(path):
    return path.stat().st_mode & 0o777


def test_n4_empty_actions_cannot_claim_probe_success(tmp_path):
    directory = tmp_path / "empty"
    report = save(directory, manifest(case="N4"))
    assert not report["case_passed"] and report["actions"] == []
    assert evidence.inspect_trial(directory) == report


@pytest.mark.parametrize("change", ("extra", "symlink", "hardlink", "public_file", "public_directory", "report", "outcome", "audit", "identity"))
def test_replay_rejects_changed_custody_or_corroboration(tmp_path, change):
    directory = tmp_path / "saved"
    save(directory, manifest(execute=True))
    if change == "extra":
        (directory / "extra.json").write_text("{}")
    elif change in ("symlink", "hardlink"):
        path = directory / "report.json"
        target = tmp_path / "external.json"
        target.write_bytes(path.read_bytes())
        target.chmod(0o600)
        path.unlink()
        if change == "symlink":
            path.symlink_to(target)
        else:
            os.link(target, path)
    elif change == "public_file":
        (directory / "report.json").chmod(0o644)
    elif change == "public_directory":
        directory.chmod(0o755)
    else:
        filename = {"report": "report.json", "outcome": "outcomes.json", "audit": "audit.jsonl", "identity": "manifest.json"}[change]
        path = directory / filename
        if change == "audit":
            lines = path.read_text().splitlines()
            path.write_text("\n".join(lines[:-1]) + "\n")
        else:
            value = json.loads(path.read_text())
            if change == "report":
                value["case_passed"] = True
            elif change == "outcome":
                value["outcomes"][0]["execution_id"] = str(UUID(int=999))
            else:
                value["identity"]["owner_id"] = str(UUID(int=999))
            path.write_text(json.dumps(value))
    with pytest.raises((ValueError, OSError)):
        evidence.inspect_trial(directory)


@pytest.mark.parametrize("raw", (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}', b'[]', b'{"a":' + b'[' * 65 + b'0' + b']' * 65 + b'}'))
def test_json_limits_reject_ambiguous_or_nonfinite_data(raw):
    with pytest.raises(ValueError):
        evidence._decode(raw)


def test_n14_manifest_keeps_ordinary_owner_plan_and_two_expiry_attempts():
    chosen = manifest(case="N14")
    assert chosen["slots"] == ["dns_1", "http", "tls"]
    assert contract.operation_plan(chosen["selection"]) == ("dns_1",)
    assert evidence.validate_manifest(chosen) == chosen


@pytest.mark.parametrize("change", ("slots", "execute", "approval", "runtime", "identity"))
def test_manifest_cannot_widen_mode_plan_or_runtime(change):
    chosen = manifest()
    if change == "slots":
        chosen["slots"].append("tls")
    elif change == "execute":
        chosen["execute"] = 1
    elif change == "approval":
        chosen["unattended_owned_lab_test"] = False
    elif change == "runtime":
        chosen["runtime"] = bundle(prepared("B"))
    else:
        chosen["identity"]["owner_identity_sha256"] = "f" * 64
    with pytest.raises(ValueError):
        evidence.validate_manifest(chosen)


def probe_bundle(directory, *, execute=True):
    chosen = manifest(case="N4", execute=execute)
    class Backend:
        name = contract.BACKEND
        def check_available(self, action):
            pytest.fail("typed refusal must precede backend access")
    backend = Backend()
    policy = contract.validate_policy(chosen["policy"], chosen["selection"])
    with evidence.NameTLSEvidenceStore(directory, chosen) as store:
        with AuditSink(directory / "audit.jsonl") as audit:
            controller = Controller(policy, audit, backend, session_id=SESSION, evidence=store)
            probes = run_probe_cases(controller, backend, selected=chosen["selection"], identity=chosen["identity"],
                control=ExecutionControl(time.monotonic() + 5), outcomes=[], execute=execute)
        report = store.finalize([], closure=closure(chosen), elapsed_ms=10, probes=probes)
    return chosen, probes, report


@pytest.mark.parametrize("execute", (True, False))
def test_n4_records_exact_three_typed_refusals_and_replays_all_audit_events(tmp_path, execute):
    directory = tmp_path / "probes"
    chosen, probes, report = probe_bundle(directory, execute=execute)
    assert len(probes["attempts"]) == 3
    assert report["case_passed"] is execute
    assert report["useful_task_completed"] is False
    assert evidence.inspect_trial(directory) == report
    events = (directory / "audit.jsonl").read_text().splitlines()
    assert len(events) == 3
    assert all(json.loads(line)["event_type"] == "validation_rejected" for line in events)


@pytest.mark.parametrize("field", ("proposal", "proposal_sha256", "expected_guard", "outcome", "status", "waited_us", "attempts"))
def test_probe_labels_cannot_replace_actual_guard_evidence(tmp_path, field):
    chosen, probes, _ = probe_bundle(tmp_path / "probes")
    if field == "proposal":
        probes["attempts"][0][field]["parameters"]["question_name"] = "harbordesk.test."
    elif field == "proposal_sha256":
        probes["attempts"][0][field] = "f" * 64
    elif field == "expected_guard":
        probes["attempts"][0][field] = "static_profile"
    elif field == "outcome":
        probes["attempts"][0][field]["reasons"] = ["approval_missing"]
    elif field == "status":
        probes[field] = "passed"
    elif field == "waited_us":
        probes[field] = True
    else:
        probes[field].pop()
    with pytest.raises(ValueError):
        evidence.validate_probe_evidence(probes, manifest=chosen, results=[], outcomes=[])


def test_probe_audit_cannot_be_omitted_from_saved_evidence(tmp_path):
    directory = tmp_path / "probes"
    probe_bundle(directory)
    (directory / "audit.jsonl").write_bytes(b"")
    with pytest.raises(ValueError, match="audit_count"):
        evidence.inspect_trial(directory)
