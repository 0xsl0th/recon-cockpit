"""Fixed workflow and CLI checks; process doubles do not establish isolation."""

import copy
import hashlib
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import cli, coordinator_isolation, openai_provider
from recon_cockpit.secure_agent.assessment import AssessmentProvider
from recon_cockpit.secure_agent.assessment_contract import assessment_action, diagnostics_path
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.openai_protocol import build_request, decode_response
from scripts.secure_agent_control_plane_demo import demo_policy


POLICY = Path(__file__).resolve().parents[1] / "examples/secure-agent-policy.json"


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def control():
    return ExecutionControl(time.monotonic() + 10, threading.Event())


class PortableParser:
    boundary_checks = None

    def __init__(self):
        self.calls = []

    def plan(self, config, observation, exchange, *, control):
        self.calls.append((config, observation, control))
        return decode_response(exchange(build_request(config, observation), control=control))


@pytest.fixture
def provider_case(monkeypatch, tmp_path):
    monkeypatch.setattr(openai_provider, "LinuxOpenAIPlanner", PortableParser)
    evidence = SimpleNamespace(records=[])
    path = tmp_path / "private-audit" / "events.jsonl"
    with AuditSink(path) as audit:
        provider = AssessmentProvider("a", audit, evidence)
        provider.bind_session(str(uuid4()))
        yield SimpleNamespace(provider=provider, evidence=evidence, path=path, control=control())


def completed_discovery(case):
    first = json.loads(case.provider.propose(encode({"step": 1, "untrusted_observation": None}),
                                               control=case.control))
    observation = encode({"step": 2, "untrusted_observation": {
        "execution_status": "succeeded", "body": "PRIVATE-DISCOVERY-BODY",
    }})
    action = first["action"]
    case.evidence.records.append({
        "execution_id": str(uuid4()), "session_step": 1, "execution_status": "succeeded",
        "action": {key: value for key, value in action.items() if key != "rationale"},
        "action_digest": parse_action(action).digest,
        "observation": {"classification": "discovered", "followup_path": diagnostics_path("a")},
        "authority_observation_sha256": hashlib.sha256(observation).hexdigest(),
    })
    return first, observation


def test_one_retained_offline_broker_follows_only_completed_matching_discovery(provider_case):
    case = provider_case
    first, observation = completed_discovery(case)
    second = json.loads(case.provider.propose(observation, control=case.control))
    assert first == {"schema_version": "1", "action": assessment_action("a", 1), "done": False}
    assert second == {"schema_version": "1", "action": assessment_action("a", 2), "done": True}
    assert dict(case.provider.broker.snapshot)["calls_reserved"] == 2
    assert case.provider.broker.snapshot["output_tokens_reserved"] == 2048
    assert case.provider.broker.limits.max_calls == 2
    assert case.provider.name == "deterministic-http-fixture-assessment"
    parser_calls = case.provider._offline._planner.calls
    assert len(parser_calls) == 2 and all(row[2] is case.control for row in parser_calls)
    assert all(row[0] is case.provider.broker.config for row in parser_calls)
    assert case.provider.boundary_checks is None
    assert "PRIVATE-DISCOVERY-BODY" not in case.path.read_text()
    with pytest.raises(RuntimeError, match="assessment_provider_closed"):
        case.provider.propose(observation, control=case.control)
    assert case.provider.broker.snapshot["calls_reserved"] == 2


@pytest.mark.parametrize("mutation", [
    "missing_record", "extra_record", "started", "failed", "wrong_step", "boolean_step",
    "wrong_action", "wrong_action_digest", "absent", "inconclusive", "wrong_path", "different_case",
    "wrong_observation_digest", "modified_authority_body", "modified_authority_status",
])
def test_invalid_discovery_stops_before_second_exchange(provider_case, mutation):
    case = provider_case
    _first, observation = completed_discovery(case)
    record = case.evidence.records[0]
    if mutation == "missing_record":
        case.evidence.records.clear()
    elif mutation == "extra_record":
        case.evidence.records.append(copy.deepcopy(record))
    elif mutation in {"started", "failed"}:
        record["execution_status"] = mutation
    elif mutation == "wrong_step":
        record["session_step"] = 2
    elif mutation == "boolean_step":
        record["session_step"] = True
    elif mutation == "wrong_action":
        record["action"]["parameters"]["path"] = "/different"
    elif mutation == "wrong_action_digest":
        record["action_digest"] = "0" * 64
    elif mutation in {"absent", "inconclusive"}:
        record["observation"]["classification"] = mutation
    elif mutation in {"wrong_path", "different_case"}:
        record["observation"]["followup_path"] = ("https://example.invalid/" if mutation == "wrong_path"
                                                 else diagnostics_path("b"))
    elif mutation == "wrong_observation_digest":
        record["authority_observation_sha256"] = "0" * 64
    else:
        modified = json.loads(observation)
        key = "body" if mutation == "modified_authority_body" else "execution_status"
        modified["untrusted_observation"][key] = "CHANGED"
        observation = encode(modified)
    result = json.loads(case.provider.propose(observation, control=case.control))
    assert result == {"schema_version": "1", "action": None, "done": True}
    assert case.provider.broker.snapshot["calls_reserved"] == 1
    assert len(case.provider._offline._planner.calls) == 1


def test_dry_run_does_not_simulate_successful_discovery(provider_case):
    case = provider_case
    case.provider.propose(encode({"step": 1, "untrusted_observation": None}), control=case.control)
    result = json.loads(case.provider.propose(encode({"step": 2, "untrusted_observation": {
        "execution_status": "dry_run", "body": "",
    }}), control=case.control))
    assert result["action"] is None and result["done"] is True
    assert case.provider.broker.snapshot["calls_reserved"] == 1


@pytest.mark.parametrize("mutation", ["target", "path", "method", "action_id", "allowance", "done", "extra"])
@pytest.mark.parametrize("step", [1, 2])
def test_compromised_parser_cannot_substitute_any_candidate(provider_case, monkeypatch, mutation, step):
    case = provider_case
    observation = encode({"step": 1, "untrusted_observation": None})
    if step == 2:
        _, observation = completed_discovery(case)
    original = case.provider._offline._planner.plan

    def forge(*args, **kwargs):
        candidate = json.loads(original(*args, **kwargs))
        if mutation == "target":
            candidate["action"]["target"] = "192.0.2.1"
        elif mutation == "path":
            candidate["action"]["parameters"]["path"] = "/changed"
        elif mutation == "method":
            candidate["action"]["parameters"]["method"] = "HEAD"
        elif mutation == "action_id":
            candidate["action"]["action_id"] = str(uuid4())
        elif mutation == "allowance":
            candidate["action"]["parameters"]["max_output_bytes"] = 2048
        elif mutation == "done":
            candidate["done"] = not candidate["done"]
        else:
            candidate["approval_reference"] = "forged"
        return encode(candidate)

    monkeypatch.setattr(case.provider._offline._planner, "plan", forge)
    with pytest.raises(ValueError):
        case.provider.propose(observation, control=case.control)
    with pytest.raises(RuntimeError, match="assessment_provider_closed"):
        case.provider.propose(observation, control=case.control)
    assert case.provider.broker.snapshot["calls_reserved"] == step


@pytest.mark.parametrize("observation", [
    b"", b"[]", b"{}", b"\xff", None, "{}", b" " * 8193,
    encode({"step": True, "untrusted_observation": None}),
    encode({"step": 2, "untrusted_observation": None}),
    encode({"step": 1, "untrusted_observation": {"body": "forged success"}}),
    encode({"step": 1, "untrusted_observation": None, "execute": True}),
])
def test_invalid_or_replayed_observation_poison_provider(provider_case, observation):
    case = provider_case
    with pytest.raises(ValueError):
        case.provider.propose(observation, control=case.control)
    with pytest.raises(RuntimeError, match="assessment_provider_closed"):
        case.provider.propose(encode({"step": 1, "untrusted_observation": None}), control=case.control)
    assert case.provider.broker.snapshot["calls_reserved"] == 0


def test_cancelled_second_step_cannot_exchange_or_reset_provider(provider_case):
    case = provider_case
    _, observation = completed_discovery(case)
    case.control.cancelled.set()
    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        case.provider.propose(observation, control=case.control)
    with pytest.raises(RuntimeError, match="broker_session_already_bound"):
        case.provider.bind_session(str(uuid4()))
    with pytest.raises(RuntimeError, match="assessment_provider_closed"):
        case.provider.propose(observation, control=control())
    assert case.provider.broker.snapshot["calls_reserved"] == 1


@pytest.fixture
def process_doubles(monkeypatch):
    seen = {"requests": [], "controls": []}
    monkeypatch.setattr(openai_provider, "LinuxOpenAIPlanner", PortableParser)

    def run(self, init, exchange, *, control):
        initial = json.loads(init)
        seen["controls"].append(control)
        for step in range(1, 17):
            request = {**initial, "sequence": step, "operation": "plan"}
            for _ in range(2):
                seen["requests"].append(copy.deepcopy(request))
                response = json.loads(exchange(encode(request), control=control))
                if response["stop"]:
                    return encode({**initial, "status": "closed"})
                request.update(operation="propose", plan=response["plan"])
        pytest.fail("authority did not stop")

    monkeypatch.setattr(coordinator_isolation.LinuxOfflineCoordinator, "run", run)
    return seen


def arguments(tmp_path, *extra):
    return ["--http-assessment", "a", "--assessment-dir", str(tmp_path / "evidence"),
            "--audit", str(tmp_path / "private-audit" / "events.jsonl"), "--policy", str(POLICY), *extra]


def test_cli_dry_run_has_private_inconclusive_report_without_manufactured_evidence(tmp_path, capsys, process_doubles):
    assert cli.main(arguments(tmp_path)) == 0
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["assessment_outcome"] == "inconclusive"
    assert summary["provider"] == "deterministic-http-fixture-assessment"
    assert summary["live_calls_enabled"] is False
    assert summary["actions_succeeded"] == 0 and summary["steps_attempted"] == 2
    assert summary["broker"]["calls_reserved"] == 1
    assert (tmp_path / "evidence" / "report.json").is_file()
    assert (tmp_path / "evidence" / "report.md").is_file()
    assert all(text not in captured.out + captured.err for text in ("rationale", "untrusted_result", '"body"'))
    report = json.loads((tmp_path / "evidence" / "report.json").read_text())
    assert report["outcome"] == "inconclusive" and report["records"] == []


def test_cli_default_policy_requires_operator_approval_before_owned_fixture(tmp_path, capsys, process_doubles, monkeypatch):
    from recon_cockpit.secure_agent import authorized_execution

    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(cli, "_human_approval", lambda *_a, **_k: pytest.fail("no manufactured human approval"))
    monkeypatch.setattr(authorized_execution.AuthorizedFixtureBackend, "check_available",
                        lambda *_a, **_k: pytest.fail("must approve before backend/evidence start"))
    assert cli.main(arguments(tmp_path, "--execute", "--fixture")) == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary["steps"][0]["reasons"] == ["noninteractive_approval_required"]
    assert summary["assessment_outcome"] == "inconclusive" and summary["actions_succeeded"] == 0
    assert summary["broker"]["calls_reserved"] == 1
    report = json.loads((tmp_path / "evidence" / "report.json").read_text())
    assert report["records"] == []


@pytest.mark.parametrize("extra", [
    ["--execute"], ["--routed"], ["--openai-model", "other"], ["--broker-max-calls", "2"],
    ["--openai-max-output-tokens", "1024"], ["--session-mock", "three_step"],
    ["--control-plane-openai-offline", "three_step"], ["--live"],
])
def test_cli_incompatible_assessment_options_fail_before_policy_or_evidence(tmp_path, monkeypatch, extra):
    monkeypatch.setattr(cli, "_read_bounded", lambda *_a, **_k: pytest.fail("must reject before policy read"))
    with pytest.raises(SystemExit) as error:
        cli.main(arguments(tmp_path, *extra))
    assert error.value.code == 2
    assert not (tmp_path / "evidence").exists()


@pytest.mark.parametrize("argv", [
    ["--http-assessment", "a"], ["--assessment-dir", "/tmp/no-assessment-source"],
    ["--inspect-assessment", "/tmp/no-assessment", "--execute"],
    ["--inspect-assessment", "/tmp/no-assessment", "--fixture"],
    ["--inspect-assessment", "/tmp/no-assessment", "--session-max-steps", "2"],
])
def test_cli_requires_assessment_directory_and_read_only_inspection(monkeypatch, argv):
    monkeypatch.setattr(cli, "_read_bounded", lambda *_a, **_k: pytest.fail("must reject before policy read"))
    with pytest.raises(SystemExit) as error:
        cli.main(argv)
    assert error.value.code == 2


def test_cli_inspection_never_opens_policy_audit_provider_or_backend(tmp_path, capsys, process_doubles, monkeypatch):
    from recon_cockpit.secure_agent import assessment, authorized_execution

    assert cli.main(arguments(tmp_path)) == 0
    capsys.readouterr()
    before = {str(path.relative_to(tmp_path / "evidence")): (path.read_bytes(), path.stat().st_mtime_ns)
              for path in (tmp_path / "evidence").rglob("*") if path.is_file()}
    monkeypatch.setattr(cli, "_read_bounded", lambda *_a, **_k: pytest.fail("inspection read policy"))
    monkeypatch.setattr(cli, "AuditSink", lambda *_a, **_k: pytest.fail("inspection opened audit"))
    monkeypatch.setattr(assessment, "AssessmentProvider", lambda *_a, **_k: pytest.fail("inspection created provider"))
    monkeypatch.setattr(authorized_execution, "AuthorizedFixtureBackend",
                        lambda *_a, **_k: pytest.fail("inspection created executor"))
    assert cli.main(["--inspect-assessment", str(tmp_path / "evidence")]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["outcome"] == "inconclusive" and report["integrity_issues"] == []
    after = {str(path.relative_to(tmp_path / "evidence")): (path.read_bytes(), path.stat().st_mtime_ns)
             for path in (tmp_path / "evidence").rglob("*") if path.is_file()}
    assert before == after


@pytest.fixture
def fixture_backend_double(monkeypatch):
    from recon_cockpit.secure_agent import authorized_execution, worker

    calls = []
    monkeypatch.setattr(authorized_execution.AuthorizedFixtureBackend, "check_available", lambda *_a, **_k: None)

    def run(self, action, policy, *, control):
        control.check()
        calls.append(action)
        http_status, body, _headers = worker._response(action.parameters.path)
        received = len(body) + 32
        row = {"target": action.target, "port": action.parameters.port, "http_status": http_status,
               "bytes_received": received, "truncated": False, "body": body.decode("utf-8"),
               "response_sha256": hashlib.sha256(body).hexdigest()}
        return {"status": "succeeded", "results": [row], "bytes_received": received, "truncated": False}

    monkeypatch.setattr(authorized_execution.AuthorizedFixtureBackend, "run", run)
    return calls


def execution_arguments(tmp_path, case="a"):
    policy_path = tmp_path / "automatic-fixture-policy.json"
    policy_path.write_text(json.dumps(demo_policy().to_dict()))
    args = arguments(tmp_path, "--execute", "--fixture", "--policy", str(policy_path))
    args[args.index("--http-assessment") + 1] = case
    return args


@pytest.mark.parametrize("case,outcome,calls", [("a", "validated", 2), ("b", "not_demonstrated", 2),
                                               ("c", "inconclusive", 2), ("f", "inconclusive", 1)])
def test_real_evidence_gates_portable_pipeline_and_reports_assessment_separately(
        tmp_path, capsys, process_doubles, fixture_backend_double, case, outcome, calls):
    assert cli.main(execution_arguments(tmp_path, case)) == 0
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["assessment_outcome"] == outcome
    assert summary["actions_succeeded"] == len(fixture_backend_double) == calls
    assert summary["broker"]["calls_reserved"] == calls
    assert summary["steps_attempted"] == 2
    directory = tmp_path / "evidence"
    report = json.loads((directory / "report.json").read_text())
    assert report["outcome"] == outcome and report["integrity_issues"] == []
    assert len(report["records"]) == len(report["finding"]["evidence"]) == calls
    assert report["finding"]["review_status"] == "pending_operator_review"
    assert all(step["execution_id"] == record["execution_id"]
               for step, record in zip(summary["steps"], report["records"]))
    for record in report["records"]:
        assert record["execution_id"] != record["action"]["action_id"]
        assert "rationale" not in record["action"]
        raw = (directory / record["artifact"]["filename"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == record["artifact"]["sha256"]
    assert "billing-db.fixture.invalid" not in captured.out + captured.err + json.dumps(report)
    assert cli.main(["--inspect-assessment", str(directory)]) == 0
    inspection = json.loads(capsys.readouterr().out)
    assert inspection["outcome"] == outcome and inspection["integrity_issues"] == []


@pytest.mark.parametrize("boundary,launches", [("start", 0), ("finish", 1), ("finalize", 2)])
def test_cli_evidence_failure_prevents_new_work_and_never_prints_success(
        tmp_path, capsys, process_doubles, fixture_backend_double, monkeypatch, boundary, launches):
    from recon_cockpit.secure_agent.evidence import EvidenceStore, EvidenceUnavailable

    def fail(*_args, **_kwargs):
        raise EvidenceUnavailable("PRIVATE-EVIDENCE-FAILURE")

    monkeypatch.setattr(EvidenceStore, boundary, fail)
    assert cli.main(execution_arguments(tmp_path)) == 3
    captured = capsys.readouterr()
    error = json.loads(captured.out)
    assert error["execution_status"] == "evidence_error"
    assert error["reasons"] == ["evidence_unavailable"]
    assert "PRIVATE-EVIDENCE-FAILURE" not in captured.out + captured.err
    assert len(fixture_backend_double) == launches
    assert not (tmp_path / "evidence" / "report.json").exists()


def test_cli_inspection_flags_missing_artifact_without_relaunch_or_body_disclosure(
        tmp_path, capsys, process_doubles, fixture_backend_double):
    assert cli.main(execution_arguments(tmp_path)) == 0
    capsys.readouterr()
    directory = tmp_path / "evidence"
    report = json.loads((directory / "report.json").read_text())
    (directory / report["records"][0]["artifact"]["filename"]).unlink()
    assert cli.main(["--inspect-assessment", str(directory)]) == 2
    captured = capsys.readouterr()
    inspection = json.loads(captured.out)
    assert inspection["outcome"] == "inconclusive" and inspection["integrity_issues"]
    assert len(fixture_backend_double) == 2
    assert "billing-db.fixture.invalid" not in captured.out + captured.err
