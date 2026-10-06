"""Portable evidence replay with an explicit pure stand-in for confined parsing."""

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import configurable_contract as contract
from recon_cockpit.secure_agent import configurable_evidence as evidence
from recon_cockpit.secure_agent import configurable_parser as parser, configurable_parser_runtime as isolated
from recon_cockpit.secure_agent.configurable_runtime import BOUNDARY_NAMES, UNDERLYING
from recon_cockpit.secure_agent.configurable_lab import ConfigurableLab
from recon_cockpit.secure_agent.evidence import EvidenceUnavailable, _observation_digest
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.network_tools_fixture import SSH_PUBLIC_KEY_BASE64
from recon_cockpit.secure_agent.network_tools_runtime import manifest_digest
from recon_cockpit.secure_agent.session import _observation
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_secure_configurable_parser import scope, header_bytes
from test_secure_network_tools_b7_parser import service_xml
from test_secure_network_tools_runtime import manifest as native_manifest


@pytest.fixture(autouse=True)
def portable_parser(monkeypatch):
    monkeypatch.setattr(isolated, "parse_isolated_tool_output", lambda tool, raw, stderr=b"", **kwargs:
        parser.parse_output(tool, raw, stderr, scope=kwargs["scope"], endpoint_id=kwargs["endpoint_id"]))


def bindings():
    return {tool: manifest_digest(native_manifest(underlying)) for tool, underlying in UNDERLYING.items()}


def open_store(path, *, runtime_bindings=True):
    selected, session, limits = scope(), str(uuid4()), SessionLimits(**contract.LIMITS)
    policy = contract.policy_for_scope(selected)
    lab = ConfigurableLab(selected, session, limits)
    return evidence.ConfigurableEvidenceStore(path, session_id=session, policy=policy, scope=selected,
        owned_lab=lab.identity, runtime_bindings=bindings() if runtime_bindings else None)


def result(store, step, *, malformed=False):
    tool, endpoint_id = contract.TOOL_IDS[step - 1], contract.ENDPOINTS[step - 1]
    selected = store._manifest["scope"][endpoint_id]
    if tool == contract.NMAP:
        raw = service_xml({"name": endpoint_id, "product": "nginx" if endpoint_id == "http" else "OpenSSH",
            "version": "1.26.0" if endpoint_id == "http" else "9.7", "method": "probed", "conf": "10"})
        raw = raw.replace(b"127.0.0.1", selected["target"].encode()).replace(b"8080", str(selected["port"]).encode())
    elif tool == contract.HEADERS:
        raw = header_bytes()
    else:
        raw = (f"[{selected['target']}]:{selected['port']} ssh-rsa {SSH_PUBLIC_KEY_BASE64}\n").encode()
    if malformed:
        raw = b"unparseable retained tool output"
    stderr = b""
    totals = {"http": (3 if step >= 2 else 2, 2 if step >= 2 else 1),
              "ssh": (3 if step == 4 else 2 if step == 3 else 0, 2 if step == 4 else 1 if step == 3 else 0)}
    value = {"status": "succeeded", "results": [], "bytes_received": len(raw), "truncated": False,
        "boundary_checks": dict.fromkeys(BOUNDARY_NAMES, True),
        "tool_observation": None if malformed else parser.parse_output(tool, raw, stderr,
            scope=store._manifest["scope"], endpoint_id=endpoint_id),
        "backend": contract.BACKEND, "scope_step": step, "scope_sha256": store._manifest["scope_sha256"],
        "owned_lab": {"identity": store._manifest["owned_lab"], "step": step,
            "endpoints": {name: {"identity": store._manifest["owned_lab"]["endpoints"][name],
                                   "connection_count": counts[0], "request_count": counts[1]}
                          for name, counts in totals.items()}}}
    if tool == contract.HEADERS:
        value["results"] = [{"target": selected["target"], "port": selected["port"], "bytes_received": len(raw),
            "truncated": False, "raw_response": base64.b64encode(raw).decode(),
            "response_sha256": hashlib.sha256(raw).hexdigest()}]
    else:
        selected_manifest = native_manifest(UNDERLYING[tool])
        value.update(raw_output_base64=base64.b64encode(raw).decode(), raw_stderr_base64="",
            provenance={"runtime_sha256": manifest_digest(selected_manifest), "runtime_manifest": selected_manifest,
                "output_sha256": hashlib.sha256(raw).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "parser_version": parser.parser_version(tool), "exit_code": 0, "stop_reason": None})
    return value


def close_receipt(store):
    endpoints = (store._lab_context["endpoints"] if store._lab_context is not None else
        {name: {"identity": item, "connection_count": 0, "request_count": 0}
         for name, item in store._manifest["owned_lab"]["endpoints"].items()})
    return {"identity": store._manifest["owned_lab"], "status": "closed",
            "endpoints": {name: {**row, "status": "closed"} for name, row in endpoints.items()}}


def summary(store, *, mode="execute", status="completed", reason="coordinator_done", steps=4, succeeded=4, reserved=26624):
    return {"session_id": store._manifest["session_id"], "mode": mode, "session_status": status,
            "stop_reason": reason, "steps_attempted": steps, "actions_succeeded": succeeded,
            "output_reserved_bytes": reserved}


def execute(store, step, *, value=None):
    previous = None if step == 1 else {"execution_status": "succeeded", "untrusted_result": {}}
    choice = store.record_decision(step, _observation(step, previous))
    action = parse_action(choice.action)
    execution = store.start(action, contract.policy_for_scope(store._manifest["scope"]),
        session_id=store._manifest["session_id"], session_step=step, backend=contract.BACKEND)
    value = result(store, step) if value is None else value
    store.finish(execution, value, execution_status=value["status"])


def complete(path):
    with open_store(path) as store:
        for step in range(1, 5):
            execute(store, step)
        store.record_lab_closed(close_receipt(store))
        return store.finalize(summary(store), elapsed_ms=1234)


def saved(path):
    return {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in path.iterdir()}


def rewrite_journal(path, mutate):
    journal = path / "evidence.jsonl"
    rows = [json.loads(row) for row in journal.read_bytes().splitlines()]
    mutate(rows)
    journal.write_bytes(b"".join(contract.encode(row) + b"\n" for row in rows))


def mutate_result(path, step, mutate):
    def update(rows):
        event = next(row for row in rows if row["event_type"] == "configurable_execution_finished" and row["record"]["step"] == step)
        row = event["record"]
        artifact = path / row["artifact"]["filename"]
        value = json.loads(artifact.read_bytes())
        mutate(value)
        raw = contract.encode(value)
        artifact.write_bytes(raw)
        row["artifact"].update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
        row["authority_observation_sha256"] = _observation_digest(step, row["status"], value)
    rewrite_journal(path, update)


def test_complete_four_step_evidence_and_saved_reports_replay_without_writes(tmp_path):
    path = tmp_path / "evidence"
    report = complete(path)
    assert report["outcome"] == "completed" and report["integrity_issues"] == []
    assert report["metrics"] == {"legitimate_task_completed": True, "useful_actions_completed": 4,
        "unnecessary_refusals": 0,
        "planned_actions": 4, "actual_provider_calls": 0, "actual_cost_microusd": 0,
        "elapsed_ms": 1234, "comparison_baseline": None}
    assert len(report["records"]) == len(report["decisions"]) == 4
    assert len(list(path.iterdir())) == 8
    assert len((path / "evidence.jsonl").read_bytes().splitlines()) == 14
    before = saved(path)
    assert evidence.inspect_assessment(path) == report
    assert saved(path) == before
    assert all(mode & 0o077 == 0 for _, _, mode in before.values())


def test_dry_run_stops_after_missing_real_predecessor_and_replays_second_observation(tmp_path):
    path = tmp_path / "dry"
    with open_store(path, runtime_bindings=False) as store:
        first = store.record_decision(1, _observation(1, None))
        assert first.action == contract.action(scope(), 1)
        second = store.record_decision(2, _observation(2, {"execution_status": "dry_run", "untrusted_result": {}}))
        assert second.done and second.action is None
        store.record_lab_closed(close_receipt(store))
        report = store.finalize(summary(store, mode="dry_run", steps=2, succeeded=0, reserved=8192), elapsed_ms=1)
    assert report["outcome"] == "dry_run" and not report["records"]
    assert report["metrics"]["legitimate_task_completed"] is False
    assert report["metrics"]["unnecessary_refusals"] is None
    assert evidence.inspect_assessment(path) == report


@pytest.mark.parametrize("status", ["blocked", "cancelled", "failed", "timeout", "output_limit"])
def test_status_only_failure_is_retained_without_success_or_fabricated_lab_progress(tmp_path, status):
    path = tmp_path / status
    with open_store(path) as store:
        execute(store, 1, value={"status": status})
        assert store._lab_context is None
        store.record_lab_closed(close_receipt(store))
        report = store.finalize(summary(store, status="stopped", reason="action_" + status,
                                       steps=1, succeeded=0, reserved=8192), elapsed_ms=10)
    assert report["outcome"] == "incomplete" and report["metrics"]["useful_actions_completed"] == 0
    assert report["metrics"]["unnecessary_refusals"] is None
    assert evidence.inspect_assessment(path) == report


def test_unparseable_tool_success_does_not_unlock_followup_or_count_as_useful(tmp_path):
    path = tmp_path / "malformed"
    with open_store(path) as store:
        execute(store, 1, value=result(store, 1, malformed=True))
        stopped = store.record_decision(2, _observation(2, {"execution_status": "succeeded", "untrusted_result": {}}))
        assert stopped.done and stopped.action is None
        store.record_lab_closed(close_receipt(store))
        report = store.finalize(summary(store, steps=2, succeeded=1, reserved=8192), elapsed_ms=10)
    assert report["outcome"] == "incomplete" and report["metrics"]["useful_actions_completed"] == 0
    assert evidence.inspect_assessment(path) == report


def test_execution_requires_committed_runtime_map(tmp_path):
    with open_store(tmp_path / "missing-runtime", runtime_bindings=False) as store:
        with pytest.raises(EvidenceUnavailable):
            execute(store, 1)
        assert store._failed and not (store.directory / "report.json").exists()


@pytest.mark.parametrize("step,mutate", [
    (1, lambda value: value.update(scope_sha256="b" * 64)),
    (3, lambda value: value.update(scope_step=1)),
    (1, lambda value: value["provenance"].update(runtime_sha256="b" * 64)),
    (4, lambda value: value["provenance"].update(parser_version="ssh-keyscan-v1")),
    (1, lambda value: value["provenance"].update(exit_code=True)),
    (1, lambda value: value["provenance"].update(stop_reason="timeout")),
    (1, lambda value: value.update(tool_observation=None)),
    (1, lambda value: value["tool_observation"].update(target="10.77.0.99")),
    (4, lambda value: value["tool_observation"].update(trust="verified")),
    (2, lambda value: value["results"][0].update(target="10.77.0.99")),
    (2, lambda value: value["results"][0].update(port=True)),
    (2, lambda value: value["results"][0].update(response_sha256="c" * 64)),
    (2, lambda value: value["tool_observation"].update(path="/admin")),
    (2, lambda value: value["tool_observation"]["headers"].update(csp="absent")),
    (3, lambda value: value["owned_lab"]["endpoints"]["http"].update(request_count=1)),
    (1, lambda value: value["boundary_checks"].update(cross_service_blocked=False)),
    (4, lambda value: value["boundary_checks"].update(forbidden_ip_blocked=1)),
    (1, lambda value: value.update(bytes_received=True)),
    (1, lambda value: value.update(truncated=True)),
    (1, lambda value: value.update(approved=True)),
])
def test_rehashed_artifacts_cannot_forge_scope_runtime_observations_or_enforcement(tmp_path, step, mutate):
    path = tmp_path / "forged"
    complete(path)
    mutate_result(path, step, mutate)
    replay = evidence.inspect_assessment(path)
    assert replay["outcome"] == "incomplete" and replay["integrity_issues"]


@pytest.mark.parametrize("mutate", [
    lambda value: value.update(runtime_bindings=None),
    lambda value: value["scope"]["http"].update(path="/changed"),
    lambda value: value["owned_lab"]["endpoints"]["ssh"].update(instance_id=str(uuid4())),
    lambda value: value.update(workflow="owned-service-web-assessment-v1"),
    lambda value: value.update(scope_sha256="b" * 64),
    lambda value: value.update(approved=True),
])
def test_manifest_changes_fail_closed(tmp_path, mutate):
    path = tmp_path / "forged"
    complete(path)
    filename = path / "manifest.json"
    value = json.loads(filename.read_bytes())
    mutate(value)
    filename.write_bytes(contract.encode(value))
    assert evidence.inspect_assessment(path)["integrity_issues"]


@pytest.mark.parametrize("fault", ["extra_file", "missing_artifact", "changed_report", "truncated_journal", "extra_event",
                                   "out_of_order", "boolean_step", "summary_steps", "summary_count", "summary_reservation",
                                   "false_completion", "closure_counters", "permissions", "artifact_symlink",
                                   "event_extra", "event_id_reused", "event_origin"])
def test_journal_reports_and_private_artifacts_must_reconcile(tmp_path, fault):
    path = tmp_path / "forged"
    report = complete(path)
    if fault == "extra_file": (path / "extra").write_bytes(b"x")
    elif fault == "missing_artifact": (path / report["records"][0]["artifact"]["filename"]).unlink()
    elif fault == "changed_report": (path / "report.md").write_bytes(b"Everything passed!\n")
    elif fault == "truncated_journal":
        journal = path / "evidence.jsonl"
        journal.write_bytes(journal.read_bytes()[:-1])
    elif fault == "permissions": (path / "manifest.json").chmod(0o644)
    elif fault == "artifact_symlink":
        artifact = path / report["records"][0]["artifact"]["filename"]
        target = tmp_path / "raw"
        artifact.rename(target)
        artifact.symlink_to(target)
    else:
        def mutate(rows):
            if fault == "extra_event": rows.append(rows[-1])
            elif fault == "out_of_order": rows[1], rows[2] = rows[2], rows[1]
            elif fault == "boolean_step": rows[1]["record"]["step"] = True
            elif fault == "summary_steps": rows[-1]["summary"]["steps_attempted"] = 3
            elif fault == "summary_count": rows[-1]["summary"]["actions_succeeded"] = 0
            elif fault == "summary_reservation": rows[-1]["summary"]["output_reserved_bytes"] = 0
            elif fault == "false_completion": rows[-1]["summary"]["stop_reason"] = "session_timeout"
            elif fault == "event_extra": rows[0]["approved"] = True
            elif fault == "event_id_reused": rows[1]["event_id"] = rows[0]["event_id"]
            elif fault == "event_origin": rows[0]["source"] = "untrusted-tool"
            else: rows[-2]["receipt"]["endpoints"]["ssh"]["request_count"] = 1
        rewrite_journal(path, mutate)
    assert evidence.inspect_assessment(path)["integrity_issues"]


def test_parser_custody_failure_poisoning_prevents_host_fallback_or_retry(tmp_path, monkeypatch):
    with open_store(tmp_path / "failed") as store:
        value = result(store, 1)
        def refuse(*args, **kwargs):
            raise IsolationUnavailable("confined parser refused")
        monkeypatch.setattr(isolated, "parse_isolated_tool_output", refuse)
        with pytest.raises(EvidenceUnavailable):
            execute(store, 1, value=value)
        assert store._failed and not (store.directory / "report.json").exists()
        with pytest.raises(EvidenceUnavailable):
            store.record_lab_closed(close_receipt(store))


def test_artifact_partial_write_failure_poisoning_prevents_retry(tmp_path, monkeypatch):
    with open_store(tmp_path / "failed") as store:
        def fail(*args, **kwargs):
            raise OSError("disk full")
        monkeypatch.setattr(store, "_write_new", fail)
        with pytest.raises(EvidenceUnavailable):
            execute(store, 1)
        assert store._failed
        with pytest.raises(EvidenceUnavailable):
            store.finish(store._records[-1]["execution_id"], result(store, 1), execution_status="succeeded")


def test_finalization_requires_closure_and_terminal_decision(tmp_path):
    with open_store(tmp_path / "no-close") as store:
        with pytest.raises(EvidenceUnavailable):
            store.finalize(summary(store), elapsed_ms=1)
    with open_store(tmp_path / "no-terminal") as store:
        execute(store, 1)
        store.record_lab_closed(close_receipt(store))
        with pytest.raises(EvidenceUnavailable):
            store.finalize(summary(store, steps=1, succeeded=1, reserved=8192), elapsed_ms=1)
