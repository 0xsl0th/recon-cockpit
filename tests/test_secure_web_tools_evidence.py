"""Portable replay contract tests; real parser custody is checked on Linux."""
import base64
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import nmap_evidence as evidence
from recon_cockpit.secure_agent import web_tools_contract as contract
from recon_cockpit.secure_agent import web_tools_parser as parser
from recon_cockpit.secure_agent import web_tools_parser_runtime as parser_runtime
from recon_cockpit.secure_agent import web_tools_runtime as runtime
from recon_cockpit.secure_agent.evidence import EvidenceUnavailable
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session import _observation
from recon_cockpit.secure_agent.web_tools_fixture import wire_response, PORTAL_PATH
from recon_cockpit.secure_agent.web_tools_lab_contract import identity
from test_secure_web_tools_parser import ffuf_output, ffuf_rows
from test_secure_web_evidence import mutate_result


@pytest.fixture(autouse=True)
def portable_parser_double(monkeypatch):
    monkeypatch.setattr(parser_runtime, "parse_isolated_tool",
                        lambda tool, raw, **kw: parser.parse_tool_output(tool, raw))


def manifest(tool):
    source, destination, data = runtime._compiled(tool)
    interpreter = "/lib64/ld-linux-x86-64.so.2"
    files = [
        {"source": runtime.EXECUTABLES[tool], "destination": runtime.FIXED_ARGV[tool][0],
         "size": 10, "sha256": "a" * 64},
        {"source": interpreter, "destination": interpreter, "size": 10, "sha256": "b" * 64},
        {"source": source, "destination": destination, "size": len(data),
         "sha256": hashlib.sha256(data).hexdigest()},
    ]
    return runtime.validate_manifest({"version": "1", "profile": runtime.PROFILE, "tool_id": tool,
        "executable": runtime.FIXED_ARGV[tool][0], "interpreter": interpreter,
        "files": sorted(files, key=lambda row: row["destination"])})


def complete(path, case="curl-ok", status="succeeded"):
    policy = parse_policy(json.loads(Path("examples/secure-agent-web-tools-policy.json").read_text()))
    action = parse_action(contract.action(case, 1))
    selected = manifest(action.tool_id)
    digest = runtime.manifest_digest(selected)
    with evidence.NmapEvidenceStore(path, session_id=str(uuid4()), policy=policy, case=case,
            owned_lab=identity(case, str(uuid4())), workflow_profile="web_tools", runtime_sha256=digest) as store:
        store.record_decision(1, _observation(1, None))
        execution = store.start(action, policy, session_id=store._manifest["session_id"],
                                session_step=1, backend=contract.BACKEND)
        raw = (wire_response(case, PORTAL_PATH) if case.startswith("curl-")
               else ffuf_output(ffuf_rows(wildcard=case == "ffuf-wildcard")))
        normalized = parser.parse_tool_output(action.tool_id, raw) if status == "succeeded" else None
        counts = {"identity": store._manifest["owned_lab"],
                  "connection_count": 1 if case.startswith("curl-") else 8,
                  "request_count": 1 if case.startswith("curl-") else 8}
        value = {"status": status, "results": [], "tool_observation": normalized,
            "bytes_received": len(raw), "truncated": False,
            "raw_output_base64": base64.b64encode(raw).decode(), "raw_stderr_base64": "",
            "boundary_checks": dict.fromkeys(contract.BOUNDARY_FIELDS, True),
            "backend": contract.BACKEND, "owned_lab": counts,
            "provenance": {"runtime_sha256": digest, "runtime_manifest": selected,
                "output_sha256": hashlib.sha256(raw).hexdigest(), "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                "parser_version": contract.parser_version(action.tool_id),
                "exit_code": 0 if status == "succeeded" else 1, "stop_reason": None}}
        store.finish(execution, value, execution_status=status)
        store.record_lab_closed({**counts, "status": "closed"})
        return store.finalize({"session_id": store._manifest["session_id"], "mode": "execute",
            "session_status": "completed", "stop_reason": "coordinator_done", "steps_attempted": 1,
            "actions_succeeded": int(status == "succeeded"), "output_reserved_bytes": 8192})


@pytest.mark.parametrize("case,outcome", [("curl-ok", "response_observed"),
    ("curl-injected", "response_observed"), ("curl-redirect", "inconclusive"),
    ("ffuf-normal", "paths_observed"), ("ffuf-injected", "paths_observed"),
    ("ffuf-wildcard", "inconclusive")])
def test_raw_evidence_replays_without_writes_and_reports_finite_facts(tmp_path, case, outcome):
    path = tmp_path / "evidence"
    report = complete(path, case)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}
    assert report["outcome"] == outcome and report["integrity_issues"] == []
    assert evidence.inspect_evidence(path) == report
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in path.iterdir()}
    assert report["summary"]["steps_attempted"] == 1 and report["live_calls_enabled"] is False
    assert "127.0.0.2" not in (path / "report.md").read_text()
    if case.startswith("ffuf-"):
        assert "missing-control" in (path / "report.md").read_text()


@pytest.mark.parametrize("change", [
    lambda r: r.update(tool_observation=None),
    lambda r: r["tool_observation"]["headers"].update(status_code=302),
    lambda r: r["boundary_checks"].update(process_creation_blocked=False),
    lambda r: r["owned_lab"].update(request_count=0),
    lambda r: r["provenance"].update(runtime_sha256="c" * 64),
    lambda r: r["provenance"].update(exit_code=60),
])
def test_rehashed_metadata_cannot_replace_replayed_observations(tmp_path, change):
    path = tmp_path / "evidence"
    complete(path)
    mutate_result(path, 1, change)
    replay = evidence.inspect_evidence(path)
    assert replay["outcome"] == "inconclusive"
    assert "journal_or_artifact_incomplete" in replay["integrity_issues"]
    assert replay["finding"]["tool_observation"] is None


def test_failed_tool_does_not_count_as_useful_completion(tmp_path):
    path = tmp_path / "evidence"
    report = complete(path, status="failed")
    assert report["outcome"] == "inconclusive" and report["summary"]["actions_succeeded"] == 0
    assert evidence.inspect_evidence(path) == report


def test_parser_unavailability_cannot_be_replaced_with_host_parsing(tmp_path, monkeypatch):
    from recon_cockpit.secure_agent.isolation import IsolationUnavailable
    def fail(*args, **kwargs):
        raise IsolationUnavailable("parser refused")
    monkeypatch.setattr(parser_runtime, "parse_isolated_tool", fail)
    with pytest.raises(EvidenceUnavailable):
        complete(tmp_path / "evidence")
    assert not (tmp_path / "evidence" / "report.json").exists()


def test_tool_evidence_cannot_enable_live_planning(tmp_path):
    path = tmp_path / "evidence"
    complete(path)
    value = json.loads((path / "manifest.json").read_text())
    value["planning_origin"] = "model_live"
    (path / "manifest.json").write_bytes(contract.encode(value))
    with pytest.raises(EvidenceUnavailable):
        evidence.inspect_evidence(path)
