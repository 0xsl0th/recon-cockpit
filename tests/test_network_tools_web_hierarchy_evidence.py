"""Portable evidence custody/replay; these doubles make no native-execution claim."""

import base64
import hashlib
import json
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_web_hierarchy_parser as parser
from recon_cockpit.secure_agent import network_tools_web_hierarchy_parser_runtime as parser_runtime
from recon_cockpit.secure_agent import network_tools_web_hierarchy_runtime as runtime
from recon_cockpit.secure_agent import nmap_evidence as evidence
from recon_cockpit.secure_agent.network_tools_web_hierarchy_receipt import encode_owner_receipt
from recon_cockpit.secure_agent.network_tools_web_hierarchy_spec import TOOL_ID, BOUNDARY_FIELDS, MAX_OWNER_BYTES
from recon_cockpit.secure_agent.network_tools_lab_contract import identity
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session import _observation
from test_network_tools_web_hierarchy_parser import sample
from test_secure_web_evidence import mutate_result


@pytest.fixture(autouse=True)
def portable_worker(monkeypatch):
    def parse(tool, out, err, **extra):
        for key in ("deadline", "control", "closure"):
            extra.pop(key, None)
        return parser.parse(tool, out, err, **extra)
    monkeypatch.setattr(parser_runtime, "parse_isolated_web_hierarchy", parse)


def manifest():
    interpreter = "/lib64/ld-linux-x86-64.so.2"
    files = [{"source": runtime.EXECUTABLE, "destination": runtime.FIXED_ARGV[0], "size": 10, "sha256": "a" * 64},
        {"source": interpreter, "destination": interpreter, "size": 10, "sha256": "b" * 64}]
    files += [{"source": src, "destination": dest, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
              for src, dest, raw in runtime.COMPILED]
    return runtime.validate_manifest({"version": "1", "profile": runtime.PROFILE, "tool_id": TOOL_ID,
        "executable": runtime.FIXED_ARGV[0], "interpreter": interpreter,
        "files": sorted(files, key=lambda row: row["destination"])})


def receipt(variant="nested", *, failed=False):
    tool, out, err, extra = sample(variant)
    selected = manifest()
    return {"status": "failed" if failed else "succeeded", "results": [],
        "tool_observation": None if failed else parser.parse(tool, out, err, **extra),
        "web_hierarchy_owner": encode_owner_receipt(extra["owner_raw"]),
        "bytes_received": len(out) + len(err), "truncated": False,
        "raw_output_base64": base64.b64encode(out).decode(), "raw_stderr_base64": base64.b64encode(err).decode(),
        "boundary_checks": dict.fromkeys(contract.BOUNDARY_FIELDS | BOUNDARY_FIELDS, True),
        "provenance": {"runtime_sha256": runtime.manifest_digest(selected), "runtime_manifest": selected,
            "output_sha256": hashlib.sha256(out).hexdigest(), "stderr_sha256": hashlib.sha256(err).hexdigest(),
            "parser_version": parser.PARSER_VERSION, "exit_code": 1 if failed else 0, "stop_reason": None}}


def complete(path, variant="nested", *, failed=False):
    value = receipt(variant, failed=failed)
    case = "web-hierarchy-" + variant
    policy = parse_policy({"schema_version": "1", "policy_version": "hierarchy-evidence-test",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": [TOOL_ID], "allowed_ports": [8080],
        "allowed_methods": [], "max_timeout_seconds": 10, "max_output_bytes": 8192,
        "max_targets": 1, "require_approval": True, "approval_ttl_seconds": 60})
    with evidence.NmapEvidenceStore(path, session_id=str(uuid4()), policy=policy, case=case,
            owned_lab=identity(case, str(uuid4())), workflow_profile="network_tools",
            runtime_sha256=value["provenance"]["runtime_sha256"]) as store:
        store.record_decision(1, _observation(1, None))
        execution = store.start(parse_action(contract.action(case)), policy,
            session_id=store._manifest["session_id"], session_step=1, backend=contract.BACKEND)
        counts = {"identity": store._manifest["owned_lab"], "connection_count": 12, "request_count": 12}
        value.update(backend=contract.BACKEND, owned_lab={**counts,
            "web_hierarchy_owner_sha256": value["web_hierarchy_owner"]["sha256"]})
        store.finish(execution, value, execution_status=value["status"])
        store.record_lab_closed({**counts, "status": "closed"})
        return store.finalize({"session_id": store._manifest["session_id"], "mode": "execute",
            "session_status": "stopped" if failed else "completed", "stop_reason": "action_failed" if failed else "coordinator_done",
            "steps_attempted": 1, "actions_succeeded": int(not failed), "output_reserved_bytes": 8192})


@pytest.mark.parametrize("variant,useful", [("nested", True), ("empty", True), ("hostile", True),
    ("wildcard", False), ("mixed-controls", False), ("redirect", False)])
def test_complete_and_ambiguous_bundles_replay_identically_through_both_inspectors(tmp_path, variant, useful):
    from recon_cockpit.secure_agent.assessment_inspection import inspect_saved_assessment
    path = tmp_path / "bundle"
    report = complete(path, variant)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}
    assert report["metrics"]["legitimate_task_completed"] is useful
    assert report["metrics"]["useful_actions_completed"] == int(useful)
    assert report["metrics"]["tested_unauthorized_actions_blocked"] == 0
    assert report["metrics"]["actual_provider_calls"] == report["metrics"]["actual_cost_microusd"] == 0
    assert report["integrity_issues"] == []
    assert evidence.inspect_evidence(path) == inspect_saved_assessment(path) == report
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}
    retained = json.loads(next(path.glob("result-*.json")).read_bytes())
    assert set(retained["web_hierarchy_owner"]) == {"filename", "bytes", "sha256", "representation"}
    assert next(path.glob("web-hierarchy-owner-*.json")).read_bytes() == sample(variant)[3]["owner_raw"]
    assert next(path.glob("result-*.json")).stat().st_size < evidence.MAX_ARTIFACT_BYTES == 65536
    assert "Bounded web hierarchy responses" in (path / "report.md").read_text()


def test_failed_process_never_acquires_usefulness_from_complete_owner_receipt(tmp_path):
    report = complete(tmp_path / "bundle", failed=True)
    assert report["outcome"] == "inconclusive" and report["summary"]["actions_succeeded"] == 0
    assert not report["metrics"]["legitimate_task_completed"]


def test_maximum_original_owner_and_client_streams_fit_full_result_custody_limit():
    value = receipt()
    tool, out, _, extra = sample()
    err = b"\r\x1b[2K" * 12
    lines, remaining = out.splitlines(), 8192 - len(out) - len(err)
    for index in range(len(lines)):
        padding = min(remaining, 2048 - len(lines[index]))
        lines[index] += b" " * padding
        remaining -= padding
    assert remaining == 0
    out = b"\n".join(lines) + b"\n"
    original = extra["owner_raw"]
    extra["owner_raw"] = original[:-1] + b" " * (MAX_OWNER_BYTES - len(original)) + b"\n"
    value.update(tool_observation=parser.parse(tool, out, err, **extra),
        web_hierarchy_owner=encode_owner_receipt(extra["owner_raw"]),
        raw_output_base64=base64.b64encode(out).decode(),
        raw_stderr_base64=base64.b64encode(err).decode(), bytes_received=len(out) + len(err),
        backend=contract.BACKEND,
        owned_lab={"identity": identity("web-hierarchy-nested", str(uuid4())),
            "connection_count": 12, "request_count": 12,
            "web_hierarchy_owner_sha256": hashlib.sha256(extra["owner_raw"]).hexdigest()})
    value["provenance"].update(output_sha256=hashlib.sha256(out).hexdigest(),
        stderr_sha256=hashlib.sha256(err).hexdigest())
    assert len(extra["owner_raw"]) == MAX_OWNER_BYTES and len(out) + len(err) == 8192
    contract.validate_tool_result(value, tool_id=TOOL_ID, execution_status="succeeded")
    assert len(evidence.contract.encode(value)) < evidence.MAX_ARTIFACT_BYTES == 65536


@pytest.mark.parametrize("fault", ["missing", "tampered", "oversize", "symlink", "hardlink", "readable", "orphan"])
def test_owner_artifact_custody_failures_make_replay_inconclusive(tmp_path, fault):
    path = tmp_path / "bundle"
    complete(path)
    owner = next(path.glob("web-hierarchy-owner-*.json"))
    if fault == "missing": owner.unlink()
    elif fault == "tampered": owner.write_bytes(owner.read_bytes() + b" ")
    elif fault == "oversize": owner.write_bytes(b"x" * (MAX_OWNER_BYTES + 1))
    elif fault == "symlink":
        other = tmp_path / "other.json"
        other.write_bytes(owner.read_bytes())
        owner.unlink()
        owner.symlink_to(other)
    elif fault == "hardlink": (tmp_path / "second.json").hardlink_to(owner)
    elif fault == "readable": owner.chmod(0o644)
    else:
        other = path / "web-hierarchy-owner-orphan.json"
        other.write_bytes(b"{}\n")
        other.chmod(0o600)
    report = evidence.inspect_evidence(path)
    assert report["outcome"] == "inconclusive" and report["integrity_issues"]
    assert not report["metrics"]["legitimate_task_completed"]


@pytest.mark.parametrize("mutation", [
    lambda result: result["tool_observation"].update(useful_task_completed=False),
    lambda result: result["tool_observation"].update(owner_sha256="0" * 64),
    lambda result: result["owned_lab"].update(web_hierarchy_owner_sha256="0" * 64),
    lambda result: result["owned_lab"].update(request_count=11),
    lambda result: result["provenance"].update(exit_code=1),
    lambda result: result["web_hierarchy_owner"].update(filename="different.json"),
    lambda result: result["web_hierarchy_owner"].update(representation="different-v1"),
    lambda result: result["boundary_checks"].update(udp_sockets_blocked=False),
])
def test_rehashed_saved_claims_must_match_retained_journal_and_contract(tmp_path, mutation):
    path = tmp_path / "bundle"
    complete(path)
    mutate_result(path, 1, mutation)
    report = evidence.inspect_evidence(path)
    assert report["outcome"] == "inconclusive" and report["integrity_issues"]
    assert not report["metrics"]["legitimate_task_completed"]


def test_owner_case_binding_applies_when_observation_is_missing():
    value = receipt(failed=True)
    raw = json.loads(base64.b64decode(value["web_hierarchy_owner"]["raw_base64"]))
    raw["diagnostic"]["case"] = "empty"
    owner = encode_owner_receipt((json.dumps(raw) + "\n").encode())
    selected = identity("web-hierarchy-nested", str(uuid4()))
    value.update(web_hierarchy_owner=owner, backend=contract.BACKEND,
        owned_lab={"identity": selected, "connection_count": 12, "request_count": 12,
                   "web_hierarchy_owner_sha256": owner["sha256"]})
    with pytest.raises(ValueError):
        contract.validate_result_context(value, selected, tool_id=TOOL_ID, execution_status="failed")


def test_cli_inspection_replays_without_writes(tmp_path, capsys):
    from recon_cockpit.secure_agent import cli
    path = tmp_path / "bundle"
    report = complete(path)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}
    assert cli.main(["--inspect-assessment", str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == report
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}


@pytest.mark.parametrize("fault", ["same_length_body", "coherent_status"])
def test_coherently_rehashed_owner_and_client_must_match_retained_journal_observation(tmp_path, fault):
    from recon_cockpit.secure_agent.assessment_inspection import inspect_saved_assessment
    path = tmp_path / "bundle"
    complete(path)
    owner_path = next(path.glob("web-hierarchy-owner-*.json"))
    result_path = next(path.glob("result-*.json"))
    owner = json.loads(owner_path.read_bytes())
    result = json.loads(result_path.read_bytes())
    out = base64.b64decode(result["raw_output_base64"])
    rows = [json.loads(line) for line in out.splitlines()]
    entry = owner["diagnostic"]["ledger"][0]
    wire = base64.b64decode(entry["response_base64"])
    if fault == "same_length_body":
        assert wire.endswith(b"bounded body")
        wire = wire[:-12] + b"changed body"
    else:
        assert entry["status_code"] == rows[0]["status"] == 200
        wire = wire.replace(b"HTTP/1.1 200", b"HTTP/1.1 403", 1)
        entry["status_code"] = rows[0]["status"] = 403
        out = b"".join(json.dumps(row, separators=(",", ":")).encode() + b"\n" for row in rows)
    entry["response_base64"] = base64.b64encode(wire).decode()
    owner_raw = (json.dumps(owner, separators=(",", ":")) + "\n").encode()
    owner_path.write_bytes(owner_raw)
    owner_sha = hashlib.sha256(owner_raw).hexdigest()
    stderr = base64.b64decode(result["raw_stderr_base64"])
    normalized = parser.parse(TOOL_ID, out, stderr, owner_raw=owner_raw,
        exit_code=0, stop_reason=None, truncated=False)
    # Coherent data still parses. Replay must compare it with the retained
    # journal observation, which the artifact mutation does not replace.
    assert normalized["useful_task_completed"]
    def change(value):
        value["web_hierarchy_owner"].update(bytes=len(owner_raw), sha256=owner_sha)
        value["owned_lab"].update(web_hierarchy_owner_sha256=owner_sha)
        value.update(tool_observation=normalized, raw_output_base64=base64.b64encode(out).decode(),
                     bytes_received=len(out) + len(stderr))
        value["provenance"].update(output_sha256=hashlib.sha256(out).hexdigest())
    mutate_result(path, 1, change)
    events = [json.loads(line) for line in (path / "evidence.jsonl").read_text().splitlines()]
    record = next(event["record"] for event in events if event["event_type"] == "assessment_execution_finished")
    changed = json.loads(result_path.read_bytes())
    restored = {**changed, "web_hierarchy_owner": encode_owner_receipt(owner_raw)}
    recomputed = contract.parse_observation(record["action"], restored, execution_status="succeeded")
    assert recomputed != record["observation"]
    # The planner-view digest covers status/body, not the full tool result.
    # Here results=[]; artifact changes are caught by the journal comparison.
    assert evidence._observation_digest(1, "succeeded", restored) == record["authority_observation_sha256"]
    for inspect in (evidence.inspect_evidence, inspect_saved_assessment):
        report = inspect(path)
        assert report["outcome"] == "inconclusive" and report["integrity_issues"]
        assert not report["metrics"]["legitimate_task_completed"]
