"""Portable C17 evidence tests using explicitly synthetic native event records."""

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_nuclei_git_fixture as fixture
from recon_cockpit.secure_agent import network_tools_nuclei_git_runtime as runtime
from recon_cockpit.secure_agent import network_tools_nuclei_runtime as c16_runtime
from recon_cockpit.secure_agent import network_tools_parser as parser
from recon_cockpit.secure_agent import network_tools_parser_runtime as parser_runtime
from recon_cockpit.secure_agent import network_tools_workflow as workflow
from recon_cockpit.secure_agent import nmap_evidence as evidence
from recon_cockpit.secure_agent.evidence import EvidenceUnavailable
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.network_tools_lab_contract import decode_owner_response, identity
from recon_cockpit.secure_agent.network_tools_runtime import manifest_digest
from recon_cockpit.secure_agent.session import _observation
from test_secure_nuclei_evidence import complete as c16_complete, snapshot
from test_secure_nuclei_git_parser import HTML, MAIN, PLAIN, RELEASE, encode, event, response
from test_secure_nuclei_owner_receipts import receipt
from test_secure_nuclei_parser import CAPTURED_MATCHED
from test_secure_web_evidence import mutate_result


@pytest.fixture(autouse=True)
def portable_parser_double(monkeypatch):
    monkeypatch.setattr(parser_runtime, "parse_isolated_tool",
        lambda tool, raw, stderr=b"", **kw: parser.parse_tool_output(tool, raw, stderr,
            owner_response=kw.get("owner_response")))
    monkeypatch.setattr(parser_runtime, "_runtime_files",
        lambda *args, **kwargs: pytest.fail("portable evidence must not launch a parser"))


def policy():
    return parse_policy(json.loads(Path("examples/secure-agent-nuclei-git-policy.json").read_text()))


def store_at(path, case="nuclei-git-main"):
    return evidence.NmapEvidenceStore(path, session_id=str(uuid4()), policy=policy(), case=case,
        owned_lab=identity(case, str(uuid4())), workflow_profile="network_tools",
        runtime_sha256=manifest_digest(runtime.manifest()))


def result(store, case, *, owner_wire=None, owner_complete=True, owner_closed=True):
    wire = fixture.response(case)
    raw = encode(event(wire, case in fixture.NUCLEI_GIT_MATCHED_CASES))
    sent = wire if owner_wire is None else owner_wire
    owner_receipt = receipt(sent, complete=owner_complete, closed=owner_closed)
    try:
        normalized = parser.parse_tool_output(runtime.TOOL_ID, raw,
            owner_response=decode_owner_response(owner_receipt, require_complete=True))
    except ValueError:
        normalized = None
    manifest = runtime.manifest()
    return {"status": "succeeded", "results": [], "tool_observation": normalized,
        "bytes_received": len(raw), "truncated": False,
        "raw_output_base64": base64.b64encode(raw).decode("ascii"), "raw_stderr_base64": "",
        "boundary_checks": dict.fromkeys(contract.BOUNDARY_FIELDS | runtime.BOUNDARY_FIELDS, True),
        "backend": contract.BACKEND,
        "owned_lab": {"identity": store._manifest["owned_lab"], "connection_count": 1,
            "request_count": 1, "owner_response": owner_receipt},
        "provenance": {"runtime_sha256": manifest_digest(manifest), "runtime_manifest": manifest,
            "output_sha256": hashlib.sha256(raw).hexdigest(),
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "parser_version": "nuclei-git-head-v1", "exit_code": 0, "stop_reason": None}}


def start(store, case):
    store.record_decision(1, _observation(1, None))
    return store.start(parse_action(contract.action(case)), policy(),
        session_id=store._manifest["session_id"], session_step=1, backend=contract.BACKEND)


def close_receipt(store):
    return {"identity": store._manifest["owned_lab"], "status": "closed",
        "connection_count": 1, "request_count": 1}


def summary(store):
    return {"session_id": store._manifest["session_id"], "mode": "execute",
        "session_status": "completed", "stop_reason": "coordinator_done", "steps_attempted": 1,
        "actions_succeeded": 1, "output_reserved_bytes": 8192}


def complete(path, case="nuclei-git-main", **kwargs):
    with store_at(path, case) as store:
        store.finish(start(store, case), result(store, case, **kwargs), execution_status="succeeded")
        store.record_lab_closed(close_receipt(store))
        return store.finalize(summary(store))


def replace_native(value, native):
    raw = encode(native)
    value.update(raw_output_base64=base64.b64encode(raw).decode("ascii"), bytes_received=len(raw))
    value["provenance"]["output_sha256"] = hashlib.sha256(raw).hexdigest()


def replace_owner(value, wire):
    value["owned_lab"]["owner_response"] = receipt(wire, complete=True, closed=True)
    value["tool_observation"]["owner_response_sha256"] = hashlib.sha256(wire).hexdigest()


def assert_inconclusive_unchanged(path, *, issue="journal_or_artifact_incomplete"):
    before = snapshot(path)
    report = evidence.inspect_evidence(path)
    assert report["outcome"] == "inconclusive"
    assert report["finding"]["tool_observation"] is None
    assert issue in report["integrity_issues"]
    assert snapshot(path) == before


@pytest.mark.parametrize("case,outcome", [
    ("nuclei-git-main", "signature_present"), ("nuclei-git-release", "signature_present"),
    ("nuclei-git-no-marker", "signature_absent"), ("nuclei-git-not-found", "signature_absent"),
    ("nuclei-git-injected", "signature_absent"),
])
def test_all_useful_outcomes_replay_unchanged_with_one_fixed_request(tmp_path, case, outcome):
    path = tmp_path / "evidence"
    report = complete(path, case)
    assert report["outcome"] == outcome and report["integrity_issues"] == []
    assert report["workflow_card"] == workflow.card_identity(case)
    assert report["workflow_card"]["version"] == "25"
    assert report["owned_lab"]["closure"] == {
        "identity": report["owned_lab"]["identity"], "status": "closed",
        "connection_count": 1, "request_count": 1}
    observed = report["finding"]["tool_observation"]
    assert observed["classification"] == outcome and observed["followup_path"] is None
    assert len(observed["details"]) == 12 and observed["details"]["vulnerability_verified"] is False
    assert observed["details"]["request"] == {"method": "GET", "url": "http://127.0.0.1:8080/.git/HEAD"}
    before = snapshot(path)
    assert evidence.inspect_evidence(path) == report and snapshot(path) == before
    assert report["terminal_decision"]["decision_kind"] == "stop"
    assert report["terminal_decision"]["action_digest"] is None


def test_hostile_marker_is_retained_only_in_private_evidence_and_cannot_request_followup(tmp_path):
    path = tmp_path / "evidence"
    report = complete(path, "nuclei-git-injected")
    raw = json.loads((path / report["records"][0]["artifact"]["filename"]).read_bytes())
    native = base64.b64decode(raw["raw_output_base64"])
    wire = decode_owner_response(raw["owned_lab"]["owner_response"], require_complete=True)
    assert b"refs/heads/main" in native and b"refs/heads/main" in wire
    assert fixture.NUCLEI_GIT_HOSTILE_NOTE.encode("ascii") in wire
    for filename in ("report.json", "report.md", "evidence.jsonl"):
        published = (path / filename).read_bytes()
        assert b"refs/heads/" not in published and b"127.0.0.2" not in published
        assert fixture.NUCLEI_GIT_HOSTILE_NOTE.encode("ascii") not in published
    with pytest.raises(ValueError, match="invalid_network_tool_step"):
        workflow.decide("nuclei-git-injected", 2, report["records"],
            _observation(2, {"execution_status": "succeeded", "untrusted_result": raw}))


def test_reports_describe_finite_markers_and_owner_agreement_without_repository_claim(tmp_path):
    path = tmp_path / "evidence"
    report = complete(path)
    limits = " ".join(report["limitations"])
    markdown = (path / "report.md").read_text()
    for text in ("/.git/HEAD", "two synthetic symbolic-reference markers", "exact supported text/plain",
            "status, content type and body", "does not verify an actual repository",
            "source exposure, exploitability or a CVE", "cannot authorize follow-up",
            "not proof of client reception", "No model is involved", "neither approvals nor execution authority"):
        assert text in limits and text in markdown
    assert "directory-listing" not in limits and "title, heading and parent link" not in limits
    assert report["capability"]["http_check"]["response_directed_followup"] is False
    assert report["live_calls_enabled"] is False


@pytest.mark.parametrize("case", ["nuclei-git-main", "nuclei-git-no-marker"])
@pytest.mark.parametrize("fault", ["content_type", "status", "body", "encoding", "chunked", "partial"])
def test_rehashed_owner_status_type_or_body_cannot_disagree_with_native(tmp_path, case, fault):
    path = tmp_path / "evidence"
    complete(path, case)
    def mutate(value):
        wire = decode_owner_response(value["owned_lab"]["owner_response"])
        if fault == "content_type":
            wire = wire.replace(PLAIN.encode(), HTML.encode()) if case == "nuclei-git-main" else wire.replace(HTML.encode(), PLAIN.encode())
        elif fault == "status": wire = wire.replace(b"200 OK", b"404 Not Found")
        elif fault == "body":
            wire = (response(RELEASE) if case == "nuclei-git-main" else
                wire.replace(b"Owned fixture content.", b"Other fixture content."))
        elif fault == "encoding": wire = wire.replace(b"Connection: close\r\n", b"Connection: close\r\nContent-Encoding: gzip\r\n")
        elif fault == "chunked": wire = wire.replace(b"Content-Type:", b"Transfer-Encoding:")
        else: wire = wire[:-1]
        replace_owner(value, wire)
    mutate_result(path, 1, mutate)
    assert_inconclusive_unchanged(path)


@pytest.mark.parametrize("fault", ["missing", "unfinished", "unclosed", "partial", "empty",
    "hash", "bytes", "extra_request", "no_request", "no_connection", "extra_connection"])
def test_complete_native_dump_cannot_hide_missing_or_incomplete_actual_send_receipts(tmp_path, fault):
    path = tmp_path / "evidence"
    complete(path)
    def mutate(value):
        sent = value["owned_lab"]["owner_response"]
        if fault == "missing": del value["owned_lab"]["owner_response"]
        elif fault == "unfinished": sent["send_complete"] = False
        elif fault == "unclosed": sent["connection_closed"] = False
        elif fault == "partial":
            wire = decode_owner_response(sent)[:11]
            replace_owner(value, wire)
            value["owned_lab"]["owner_response"]["send_complete"] = False
        elif fault == "empty":
            value["owned_lab"]["owner_response"] = receipt(closed=True)
            value["tool_observation"]["owner_response_sha256"] = hashlib.sha256(b"").hexdigest()
        elif fault == "hash": sent["response_sha256"] = "a" * 64
        elif fault == "bytes": sent["bytes_sent"] += 1
        elif fault == "extra_request": value["owned_lab"]["request_count"] = 2
        elif fault == "no_request": value["owned_lab"]["request_count"] = 0
        elif fault == "no_connection": value["owned_lab"]["connection_count"] = 0
        else: value["owned_lab"]["connection_count"] = 2
    mutate_result(path, 1, mutate)
    assert_inconclusive_unchanged(path)


@pytest.mark.parametrize("case,reported", [("nuclei-git-main", False), ("nuclei-git-release", False),
    ("nuclei-git-no-marker", True), ("nuclei-git-not-found", True), ("nuclei-git-injected", True)])
def test_rehashed_native_matcher_and_typed_result_cannot_override_finite_predicate(tmp_path, case, reported):
    path = tmp_path / "evidence"
    complete(path, case)
    def mutate(value):
        replace_native(value, event(fixture.response(case), reported))
        value["tool_observation"].update(matcher_status=reported,
            outcome="signature_present" if reported else "signature_absent")
    mutate_result(path, 1, mutate)
    assert_inconclusive_unchanged(path)


@pytest.mark.parametrize("fault", ["template", "template_id", "template_path", "request", "response_type",
    "error", "extra", "matcher_type", "native_body", "claim", "reference", "followup", "scratch", "exit", "truncated"])
def test_rehashed_native_schema_and_result_claims_cannot_broaden_the_fixed_observation(tmp_path, fault):
    path = tmp_path / "evidence"
    complete(path)
    def mutate(value):
        native = json.loads(base64.b64decode(value["raw_output_base64"]))
        if fault == "template": native["template"] = "directory-listing.yaml"
        elif fault == "template_id": native["template-id"] = "recon-owned-directory-listing-v1"
        elif fault == "template_path": native["template-path"] = "/tool/data/directory-listing.yaml"
        elif fault == "request": native["request"] = native["request"].replace("/.git/HEAD", "/.git/config")
        elif fault == "response_type": native["response"] = native["response"].replace(PLAIN, HTML)
        elif fault == "error": native["error"] = ""
        elif fault == "extra": native["extracted-results"] = ["refs/heads/main"]
        elif fault == "matcher_type": native["matcher-status"] = 1
        elif fault == "native_body": native["response"] = response(RELEASE).decode("ascii")
        elif fault == "claim": value["tool_observation"]["vulnerability_verified"] = True
        elif fault == "reference": value["tool_observation"]["ref"] = "refs/heads/main"
        elif fault == "followup": value["tool_observation"]["followup"] = "http://127.0.0.1:8080/.git/config"
        elif fault == "scratch": value["boundary_checks"]["scratch_noexec"] = False
        elif fault == "exit": value["provenance"]["exit_code"] = 1
        else: value["truncated"] = True
        replace_native(value, native)
    mutate_result(path, 1, mutate)
    assert_inconclusive_unchanged(path)


@pytest.mark.parametrize("direction", ["c16_into_c17", "c17_into_c16"])
@pytest.mark.parametrize("fault", ["runtime", "template", "native"])
def test_c16_and_c17_evidence_cannot_exchange_runtime_templates_or_native_records(tmp_path, direction, fault):
    path = tmp_path / "evidence"
    other = c16_runtime if direction == "c16_into_c17" else runtime
    complete(path) if direction == "c16_into_c17" else c16_complete(path)
    def mutate(value):
        if fault == "runtime":
            value["provenance"]["runtime_manifest"] = other.manifest()
            value["provenance"]["runtime_sha256"] = manifest_digest(other.manifest())
        elif fault == "template":
            original = value["provenance"]["runtime_manifest"]
            alternate = next(row for row in other.manifest()["files"] if row["source"] == "compiled:nuclei-template")
            original["files"] = [deepcopy(alternate) if row["source"] == "compiled:nuclei-template" else row
                for row in original["files"]]
            value["provenance"]["runtime_sha256"] = hashlib.sha256(contract.encode(original)).hexdigest()
        else:
            native = (json.loads(CAPTURED_MATCHED) if direction == "c16_into_c17" else
                event(fixture.response("nuclei-git-main"), True))
            replace_native(value, native)
    mutate_result(path, 1, mutate)
    # Also rehash the outer runtime commitment: the exact profile still rejects a swap.
    if fault in ("runtime", "template"):
        manifest_path = path / "manifest.json"
        saved = json.loads(manifest_path.read_bytes())
        events = [json.loads(line) for line in (path / "evidence.jsonl").read_text().splitlines()]
        finished = next(row for row in events if row["event_type"] == "assessment_execution_finished")
        artifact = json.loads((path / finished["record"]["artifact"]["filename"]).read_bytes())
        saved["runtime_sha256"] = artifact["provenance"]["runtime_sha256"]
        manifest_path.write_bytes(contract.encode(saved))
    assert_inconclusive_unchanged(path)


@pytest.mark.parametrize("sent,closed", [(b"", False), (b"", True), (b"HTTP/1.1 2", False), (b"HTTP/1.1 2", True)])
def test_successful_process_with_actual_incomplete_send_is_durable_inconclusive_evidence(tmp_path, sent, closed):
    path = tmp_path / "evidence"
    report = complete(path, owner_wire=sent, owner_complete=False, owner_closed=closed)
    assert report["outcome"] == "inconclusive" and report["integrity_issues"] == []
    assert report["records"][0]["execution_status"] == "succeeded"
    assert report["records"][0]["observation"]["classification"] == "inconclusive"
    assert report["records"][0]["observation"]["details"] is None
    before = snapshot(path)
    assert evidence.inspect_evidence(path) == report and snapshot(path) == before


@pytest.mark.parametrize("fault", ["unfinished", "unclosed", "wrong_type", "wrong_body", "native_false"])
def test_capture_refuses_a_useful_result_without_complete_matching_independent_evidence(tmp_path, fault):
    path = tmp_path / "evidence"
    with store_at(path) as store:
        execution = start(store, "nuclei-git-main")
        value = result(store, "nuclei-git-main")
        if fault == "unfinished": value["owned_lab"]["owner_response"]["send_complete"] = False
        elif fault == "unclosed": value["owned_lab"]["owner_response"]["connection_closed"] = False
        elif fault == "wrong_type": replace_owner(value, response(MAIN, content_type=HTML))
        elif fault == "wrong_body": replace_owner(value, response(RELEASE))
        else: replace_native(value, event(fixture.response("nuclei-git-main"), False))
        with pytest.raises(EvidenceUnavailable):
            store.finish(execution, value, execution_status="succeeded")
    assert not (path / "report.json").exists()


@pytest.mark.parametrize("fault", ["missing", "requests", "connections", "identity", "status", "owner_transcript"])
def test_closure_is_required_and_cannot_change_acknowledged_counters_or_identity(tmp_path, fault):
    path = tmp_path / "evidence"
    with store_at(path) as store:
        store.finish(start(store, "nuclei-git-main"), result(store, "nuclei-git-main"), execution_status="succeeded")
        closed = close_receipt(store)
        if fault != "missing":
            if fault == "requests": closed["request_count"] = 0
            elif fault == "connections": closed["connection_count"] = 0
            elif fault == "identity": closed["identity"] = identity("nuclei-git-main", str(uuid4()))
            elif fault == "status": closed["status"] = "running"
            else: closed["owner_response"] = receipt(b"invented", complete=True, closed=True)
            with pytest.raises(EvidenceUnavailable):
                store.record_lab_closed(closed)
        with pytest.raises(EvidenceUnavailable):
            store.finalize(summary(store))
    assert not (path / "report.json").exists()


@pytest.mark.parametrize("fault", ["missing", "request", "status", "identity"])
def test_replay_requires_the_matching_owner_closure_after_a_valid_capture(tmp_path, fault):
    path = tmp_path / "evidence"
    complete(path)
    journal = path / "evidence.jsonl"
    events = [json.loads(line) for line in journal.read_text().splitlines()]
    closed = next(row for row in events if row["event_type"] == "assessment_owned_lab_closed")
    if fault == "missing": events.remove(closed)
    elif fault == "request": closed["receipt"]["request_count"] = 0
    elif fault == "status": closed["receipt"]["status"] = "running"
    else: closed["receipt"]["identity"] = identity("nuclei-git-main", str(uuid4()))
    journal.write_bytes(b"\n".join(contract.encode(row) for row in events) + b"\n")
    before = snapshot(path)
    replay = evidence.inspect_evidence(path)
    assert replay["outcome"] == "inconclusive" and "owned_lab_closure_missing" in replay["integrity_issues"]
    assert replay["finding"]["tool_observation"] is None and snapshot(path) == before


def test_provider_stops_after_one_proposal_and_cannot_use_hostile_result_as_another_request(tmp_path):
    with store_at(tmp_path / "evidence", "nuclei-git-injected") as store:
        provider = workflow.NetworkToolsProvider("nuclei-git-injected", store)
        provider.bind_session(store._manifest["session_id"])
        control = ExecutionControl(time.monotonic() + 10)
        proposal = json.loads(provider.propose(_observation(1, None), control=control))
        assert proposal["done"] is True and proposal["action"] == contract.action("nuclei-git-injected")
        hostile = _observation(2, {"execution_status": "succeeded", "untrusted_result": {
            "body": fixture.NUCLEI_GIT_HOSTILE_NOTE, "ref": "refs/heads/release",
            "next_target": "http://127.0.0.2:8081/private/"}})
        with pytest.raises(RuntimeError, match="provider_closed"):
            provider.propose(hostile, control=control)
        assert len(store._decisions) == 1
