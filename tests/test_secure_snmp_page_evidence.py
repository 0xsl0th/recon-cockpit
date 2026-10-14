"""Finite page replay checks local consistency, never execution permission."""

import base64
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import assessment_inspection
from recon_cockpit.secure_agent import nmap_evidence as evidence
from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_parser as parser
from recon_cockpit.secure_agent import network_tools_parser_runtime as parser_runtime
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_snmp_page_parser as page_parser
from recon_cockpit.secure_agent import network_tools_snmp_page_spec as spec
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.network_tools_lab_contract import identity
from recon_cockpit.secure_agent.session import _observation
from test_secure_network_tools_evidence import manifest
from test_secure_snmp_page_parser import output, row, SEED
from test_secure_web_evidence import mutate_result


@pytest.fixture(autouse=True)
def portable_parser_double(monkeypatch):
    monkeypatch.setattr(parser_runtime, "parse_isolated_tool",
        lambda tool, raw, stderr=b"", **kwargs: parser.parse_tool_output(tool, raw, stderr))


def snapshot(path):
    return {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in path.iterdir()}


def complete(path, case="snmp-page-ok", *, raw=None, status="succeeded"):
    policy = parse_policy(json.loads(Path("examples/secure-agent-snmp-page-policy.json").read_text()))
    action = parse_action(contract.action(case, 1))
    selected = manifest(action.tool_id)
    digest = runtime.manifest_digest(selected)
    raw = output(case) if raw is None else raw
    normalized = None
    if status == "succeeded":
        try:
            normalized = parser.parse_tool_output(action.tool_id, raw)
        except ValueError:
            pass
    with evidence.NmapEvidenceStore(path, session_id=str(uuid4()), policy=policy, case=case,
            owned_lab=identity(case, str(uuid4())), workflow_profile="network_tools", runtime_sha256=digest) as store:
        store.record_decision(1, _observation(1, None))
        execution = store.start(action, policy, session_id=store._manifest["session_id"],
            session_step=1, backend=contract.BACKEND)
        counts = {"identity": store._manifest["owned_lab"], "connection_count": 1, "request_count": 1}
        value = {"status": status, "results": [], "tool_observation": normalized,
            "bytes_received": len(raw), "truncated": False,
            "raw_output_base64": base64.b64encode(raw).decode(), "raw_stderr_base64": "",
            "boundary_checks": dict.fromkeys(contract.BOUNDARY_FIELDS, True),
            "backend": contract.BACKEND, "owned_lab": counts,
            "provenance": {"runtime_sha256": digest, "runtime_manifest": selected,
                "output_sha256": hashlib.sha256(raw).hexdigest(), "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                "parser_version": spec.PARSER_VERSION, "exit_code": 0 if status == "succeeded" else 1,
                "stop_reason": None}}
        store.finish(execution, value, execution_status=status)
        store.record_lab_closed({**counts, "status": "closed"})
        return store.finalize({"session_id": store._manifest["session_id"], "mode": "execute",
            "session_status": "completed", "stop_reason": "coordinator_done", "steps_attempted": 1,
            "actions_succeeded": int(status == "succeeded"), "output_reserved_bytes": 8192})


@pytest.mark.parametrize("case", spec.SUCCESS_CASES)
def test_every_useful_page_replays_through_both_inspectors_without_writes_or_followup(tmp_path, case):
    path = tmp_path / "evidence"
    report = complete(path, case)
    assert report["outcome"] == "snmp_interface_page_observed" and report["integrity_issues"] == []
    assert report["metrics"]["legitimate_task_completed"] is True
    assert report["metrics"]["useful_actions_completed"] == 1
    assert report["metrics"]["actual_provider_calls"] == report["metrics"]["actual_cost_microusd"] == 0
    assert len(report["records"]) == 1 and report["records"][0]["observation"]["followup_path"] is None
    details = report["finding"]["tool_observation"]["details"]
    assert details == page_parser.parse_output(output(case))
    assert details["inventory_complete"] is details["service_identity_verified"] is False
    before = snapshot(path)
    assert evidence.inspect_evidence(path) == assessment_inspection.inspect_saved_assessment(path) == report
    assert snapshot(path) == before
    markdown = (path / "report.md").read_text()
    assert "## SNMP interface page metadata" in markdown
    assert "| Returned OID | Kind | Interface index | Description |" in markdown
    assert '| max_repetitions | `4` |' in markdown
    assert '| inventory_complete | `false` |' in markdown
    for entry in details["rows"]:
        assert '| `"' + entry["returned_oid"] + '"` | `"' + entry["kind"] + '"` |' in markdown
    assert "No returned OID was followed" in markdown
    if case == "snmp-page-empty":
        assert '| `"' + SEED + '.1"` | `"interface_description"` | `1` | `""` |' in markdown


@pytest.mark.parametrize("case", ["snmp-page-short", "snmp-page-empty-page", "snmp-page-nonincreasing",
    "snmp-page-duplicate", "snmp-page-wrong-type", "snmp-page-extra-varbind", "snmp-page-after-end"])
def test_successful_process_with_invalid_page_is_not_useful(tmp_path, case):
    path = tmp_path / "evidence"
    report = complete(path, case)
    assert report["outcome"] == "inconclusive"
    assert report["metrics"]["legitimate_task_completed"] is False
    assert report["metrics"]["useful_actions_completed"] == 0
    assert report["finding"]["tool_observation"]["details"] is None
    assert evidence.inspect_evidence(path) == assessment_inspection.inspect_saved_assessment(path) == report


def test_successful_looking_page_does_not_override_failed_process(tmp_path):
    report = complete(tmp_path / "evidence", status="failed")
    assert report["outcome"] == "inconclusive"
    assert report["metrics"]["legitimate_task_completed"] is False
    assert report["summary"]["actions_succeeded"] == 0


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(tool_observation=None),
    lambda r: r["tool_observation"].update(inventory_complete=True),
    lambda r: r["tool_observation"].update(service_identity_verified=True),
    lambda r: r["tool_observation"].update(query_oid=".1.3.6.1"),
    lambda r: r["tool_observation"].update(max_repetitions=40),
    lambda r: r["tool_observation"].update(page_full=False),
    lambda r: r["tool_observation"].update(end_boundary={"kind": "end_of_mib_view", "returned_oid": SEED}),
    lambda r: r["tool_observation"]["rows"][1].update(description="forged"),
    lambda r: r["tool_observation"]["rows"][1].update(interface_index=99),
    lambda r: r["tool_observation"].update(next_oid=SEED + ".5"),
    lambda r: r["owned_lab"].update(request_count=0),
    lambda r: r["owned_lab"].update(request_count=2),
    lambda r: r["owned_lab"].update(connection_count=2),
    lambda r: r["provenance"].update(exit_code=1),
    lambda r: r["provenance"].update(runtime_sha256="f" * 64),
    lambda r: r["boundary_checks"].update(forbidden_ip_blocked=False),
])
def test_rehashed_saved_claims_must_match_capture_contract_and_retained_journal(tmp_path, mutation):
    path = tmp_path / "evidence"
    complete(path)
    mutate_result(path, 1, mutation)
    before = snapshot(path)
    for inspect in (evidence.inspect_evidence, assessment_inspection.inspect_saved_assessment):
        report = inspect(path)
        assert report["outcome"] == "inconclusive" and report["integrity_issues"]
        assert report["metrics"]["legitimate_task_completed"] is False
    assert snapshot(path) == before


@pytest.mark.parametrize("case", ["snmp-page-empty", "snmp-page-end-of-view", "snmp-page-mixed-boundary"])
def test_coherently_rehashed_valid_capture_is_checked_against_original_journal(tmp_path, case):
    path = tmp_path / "evidence"
    complete(path)
    raw = output(case)
    normalized = page_parser.parse_output(raw)
    def mutate(result):
        result.update(raw_output_base64=base64.b64encode(raw).decode(), bytes_received=len(raw),
            tool_observation=normalized)
        result["provenance"]["output_sha256"] = hashlib.sha256(raw).hexdigest()
    mutate_result(path, 1, mutate)
    result = json.loads(next(path.glob("result-*.json")).read_bytes())
    events = [json.loads(line) for line in (path / "evidence.jsonl").read_text().splitlines()]
    record = next(event["record"] for event in events if event["event_type"] == "assessment_execution_finished")
    assert contract.parse_observation(record["action"], result, execution_status="succeeded") != record["observation"]
    # The authority digest covers the bounded planner view, not this full result.
    # Local journal consistency detects the changed capture and parsed page.
    assert evidence._observation_digest(1, "succeeded", result) == record["authority_observation_sha256"]
    for inspect in (evidence.inspect_evidence, assessment_inspection.inspect_saved_assessment):
        report = inspect(path)
        assert report["outcome"] == "inconclusive" and report["integrity_issues"]
        assert report["metrics"]["legitimate_task_completed"] is False


def test_hostile_description_remains_literal_but_is_not_markdown_or_an_action(tmp_path):
    path = tmp_path / "evidence"
    text = 'X`|* [link](https://127.0.0.2) <b>&'
    raw = b"".join(row(SEED + "." + str(i), text.encode("ascii")) for i in range(1, 5))
    report = complete(path, raw=raw)
    details = report["finding"]["tool_observation"]["details"]
    assert details["rows"][0]["description"] == text
    assert report["outcome"] == "snmp_interface_page_observed"
    assert len(report["records"]) == 1 and report["records"][0]["observation"]["followup_path"] is None
    markdown = (path / "report.md").read_text()
    assert text not in markdown and "<b>" not in markdown
    literal = r'`"X\u0060\u007c* [link](https://127.0.0.2) \u003cb\u003e\u0026"`'
    assert markdown.count(literal) == 4
    assert '| `"' + SEED + '.1"` | `"interface_description"` | `1` | ' + literal + ' |' in markdown


def test_cli_saved_inspection_has_no_evidence_writes(tmp_path, capsys):
    from recon_cockpit.secure_agent import cli
    path = tmp_path / "evidence"
    report = complete(path)
    before = snapshot(path)
    assert cli.main(["--inspect-assessment", str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == report
    assert snapshot(path) == before
