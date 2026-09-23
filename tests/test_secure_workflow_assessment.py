"""Workflow provider and CLI regressions with explicit portable process doubles."""

import hashlib
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import cli, coordinator_isolation, openai_provider, workflow
from recon_cockpit.secure_agent.assessment import WorkflowAssessmentProvider
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.authorized_execution import AuthorizedDiscoveryFixtureBackend
from recon_cockpit.secure_agent.discovery_contract import discovery_action
from recon_cockpit.secure_agent.evidence import EvidenceStore, EvidenceUnavailable, inspect_assessment
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.openai_broker import BrokerLimits
from recon_cockpit.secure_agent.openai_protocol import build_request, decode_response
from recon_cockpit.secure_agent.session import _observation
from recon_cockpit.secure_agent.worker import _response


POLICY = Path(__file__).resolve().parents[1] / "examples/secure-agent-discovery-policy.json"


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def policy(**changes):
    return parse_policy({**json.loads(POLICY.read_text()), "require_approval": False, **changes})


def result(action):
    if action.tool_id == "tcp_connect":
        return {"status": "succeeded", "bytes_received": 0, "truncated": False,
                "results": [{"target": "127.0.0.1", "port": 8080, "state": "open"}]}
    path = action.parameters.path
    if path in {"/assessment/d/diagnostics.json", "/assessment/e/diagnostics.json"}:
        return {"status": "timeout" if "/d/" in path else "output_limit"}
    status, body, _ = _response(path)
    return {"status": "succeeded", "bytes_received": len(body) + 64, "truncated": False,
            "results": [{"target": action.target, "port": action.parameters.port, "http_status": status,
                         "body": body.decode(), "bytes_received": len(body) + 64, "truncated": False,
                         "response_sha256": hashlib.sha256(body).hexdigest()}]}


class PortableParser:
    boundary_checks = None

    def plan(self, config, observation, exchange, *, control):
        return decode_response(exchange(build_request(config, observation), control=control))


@pytest.fixture
def process_doubles(monkeypatch):
    monkeypatch.setattr(openai_provider, "LinuxOpenAIPlanner", PortableParser)

    def run(self, init, exchange, *, control):
        initial = json.loads(init)
        for step in range(1, 17):
            request = {**initial, "sequence": step, "operation": "plan"}
            for _ in range(2):
                response = json.loads(exchange(encode(request), control=control))
                if response["stop"]:
                    return encode({**initial, "status": "closed"})
                request.update(operation="propose", plan=response["plan"])
        pytest.fail("authority did not stop")

    monkeypatch.setattr(coordinator_isolation.LinuxOfflineCoordinator, "run", run)


@pytest.fixture
def backend_double(monkeypatch):
    calls = []
    monkeypatch.setattr(AuthorizedDiscoveryFixtureBackend, "check_available", lambda *_: None)

    def run(self, action, policy, *, control):
        control.check()
        calls.append(action.to_dict())
        return result(action)

    monkeypatch.setattr(AuthorizedDiscoveryFixtureBackend, "run", run)
    return calls


@pytest.fixture
def provider_case(tmp_path, monkeypatch):
    monkeypatch.setattr(openai_provider, "LinuxOpenAIPlanner", PortableParser)
    session_id, selected_policy = str(uuid4()), policy()
    directory = tmp_path / "evidence"
    with AuditSink(tmp_path / "audit" / "events.jsonl") as audit, EvidenceStore(
            directory, session_id=session_id, policy=selected_policy, case="a", discovery=True, workflow=True) as evidence:
        provider = WorkflowAssessmentProvider("a", audit, evidence)
        provider.bind_session(session_id)
        yield SimpleNamespace(provider=provider, evidence=evidence, directory=directory,
                              session_id=session_id, policy=selected_policy,
                              control=ExecutionControl(time.monotonic() + 20, threading.Event()))


def journal(directory):
    return [json.loads(line) for line in (directory / "evidence.jsonl").read_text().splitlines()]


def finish_first(case):
    plan = json.loads(case.provider.propose(_observation(1, None), control=case.control))
    action = parse_action(plan["action"])
    execution = case.evidence.start(action, case.policy, session_id=case.session_id, session_step=1,
                                    backend="linux-authorized-discovery-fixture-executor-v1")
    raw = result(action)
    case.evidence.finish(execution, raw, execution_status="succeeded")
    return _observation(2, {"execution_status": "succeeded", "untrusted_result": raw})


def arguments(tmp_path, *, case="a", execute=True, policy_changes=None):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy(**(policy_changes or {})).to_dict()))
    return ["--workflow-assessment", case, "--assessment-dir", str(tmp_path / "evidence"),
            "--policy", str(path), "--audit", str(tmp_path / "audit" / "events.jsonl"),
            *(["--execute", "--fixture"] if execute else ["--dry-run"])]


@pytest.mark.parametrize("case,outcome,succeeded,exchanges", [
    ("a", "validated", 3, 3), ("b", "not_demonstrated", 3, 3), ("c", "inconclusive", 3, 3),
    ("d", "inconclusive", 2, 3), ("e", "inconclusive", 2, 3), ("f", "inconclusive", 2, 2),
])
def test_workflow_cli_six_cases_have_complete_decision_trace(
        tmp_path, capsys, process_doubles, backend_double, case, outcome, succeeded, exchanges):
    assert cli.main(arguments(tmp_path, case=case)) == (2 if case in "de" else 0)
    output = json.loads(capsys.readouterr().out)
    assert output["assessment_outcome"] == outcome and output["actions_succeeded"] == succeeded
    assert output["broker"]["calls_reserved"] == len(backend_double) == exchanges
    directory = tmp_path / "evidence"
    report = json.loads((directory / "report.json").read_text())
    assert report["workflow_card"] == workflow.card_identity()
    assert report["integrity_issues"] == [] and report["outcome"] == outcome
    assert len(report["decision_trace"]) == 3
    for index, decision in enumerate(report["decision_trace"]):
        assert decision["predecessors"] == [
            {key: row[key] for key in ("execution_id", "observation_id")}
            for row in report["records"][:index]]
        assert decision["workflow_digest"] == workflow.card_digest()
        if decision["decision_kind"] == "propose":
            assert decision["execution_id"] == report["records"][index]["execution_id"]
            assert decision["action_digest"] == report["records"][index]["action_digest"]
        else:
            assert case == "f" and decision["reason"] == "fixture_index_not_established"
            assert decision["execution_status"] == "not_proposed"
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.iterdir()}
    assert cli.main(["--inspect-assessment", str(directory)]) == 0
    assert json.loads(capsys.readouterr().out) == report
    assert before == {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.iterdir()}


def test_decision_is_durable_before_each_broker_exchange(provider_case, monkeypatch):
    case, observed = provider_case, []
    original = case.provider._offline.propose

    def propose(observation, *, control):
        rows = journal(case.directory)
        decision = rows[-1]
        assert decision["event_type"] == "assessment_workflow_decision"
        assert decision["decision"]["step"] == json.loads(observation)["step"]
        assert decision["decision"]["action_digest"] == parse_action(
            discovery_action("a", len(observed) + 1)).digest
        observed.append(decision["decision"])
        return original(observation, control=control)

    monkeypatch.setattr(case.provider._offline, "propose", propose)
    observation = finish_first(case)
    second = json.loads(case.provider.propose(observation, control=case.control))
    assert second["action"] == discovery_action("a", 2)
    assert len(observed) == case.provider.broker.snapshot["calls_reserved"] == 2


@pytest.mark.parametrize("when", ["before_decision", "after_decision"])
def test_cancellation_prevents_exchange_and_closes_provider(provider_case, monkeypatch, when):
    case = provider_case
    original = case.evidence.record_decision
    if when == "before_decision":
        case.control.cancelled.set()
    else:
        def decide(step, observation):
            decision = original(step, observation)
            case.control.cancelled.set()
            return decision
        monkeypatch.setattr(case.evidence, "record_decision", decide)
    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        case.provider.propose(_observation(1, None), control=case.control)
    assert case.provider.broker.snapshot["calls_reserved"] == 0
    case.control.cancelled.clear()
    with pytest.raises(RuntimeError, match="assessment_provider_closed"):
        case.provider.propose(_observation(1, None), control=case.control)
    assert len(journal(case.directory)) == (0 if when == "before_decision" else 1)


def test_failed_decision_write_prevents_exchange_and_latches_failure(provider_case, monkeypatch):
    case = provider_case

    def fail(_value):
        raise OSError("PRIVATE WRITE ERROR")

    monkeypatch.setattr(case.evidence, "_emit", fail)
    with pytest.raises(EvidenceUnavailable, match="^evidence_unavailable$"):
        case.provider.propose(_observation(1, None), control=case.control)
    assert case.provider.broker.snapshot["calls_reserved"] == 0
    assert journal(case.directory) == []
    with pytest.raises(RuntimeError, match="assessment_provider_closed"):
        case.provider.propose(_observation(1, None), control=case.control)
    with pytest.raises(EvidenceUnavailable):
        case.evidence.record_decision(1, _observation(1, None))


@pytest.mark.parametrize("mutation", ["target", "allowance", "action_id", "done", "tool", "rationale"])
def test_compromised_parser_cannot_substitute_a_card_candidate(provider_case, monkeypatch, mutation):
    case = provider_case
    original = case.provider._offline._planner.plan

    def plan(*args, **kwargs):
        raw = json.loads(original(*args, **kwargs))
        if mutation == "done":
            raw["done"] = True
        elif mutation == "allowance":
            raw["action"]["parameters"]["max_output_bytes"] = 2048
        else:
            raw["action"][mutation] = {"target": "127.0.0.2", "action_id": str(uuid4()),
                                        "tool": "http_probe", "rationale": "unreviewed"}[mutation]
            if mutation == "tool":
                raw["action"]["tool_id"] = raw["action"].pop("tool")
        return encode(raw)

    monkeypatch.setattr(case.provider._offline._planner, "plan", plan)
    with pytest.raises(ValueError):
        case.provider.propose(_observation(1, None), control=case.control)
    assert case.provider.broker.snapshot["calls_reserved"] == 1
    assert case.evidence.records == []
    assert journal(case.directory)[0]["decision"]["action_digest"] == parse_action(discovery_action("a", 1)).digest
    with pytest.raises(RuntimeError, match="assessment_provider_closed"):
        case.provider.propose(_observation(2, None), control=case.control)


@pytest.mark.parametrize("mode,options,policy_changes,executions,proposals,reason", [
    ("dry", [], {}, 0, 1, "dry_run_has_no_execution_evidence"),
    ("execute", [], {"allowed_tools": ["http_probe"]}, 0, 1, "proposal_denied"),
    ("execute", [], {"require_approval": True}, 0, 1, "noninteractive_approval_required"),
    ("execute", ["--session-max-output-bytes", "1"], {}, 0, 1, "output_limit"),
    ("execute", ["--session-max-output-bytes", "1024"], {}, 1, 2, "output_limit"),
    ("execute", ["--session-max-steps", "1"], {}, 1, 1, "step_limit"),
])
def test_proposals_do_not_override_dry_run_approval_policy_or_budget(
        tmp_path, capsys, process_doubles, backend_double, mode, options, policy_changes,
        executions, proposals, reason):
    args = arguments(tmp_path, execute=mode == "execute", policy_changes=policy_changes)
    assert cli.main([*args, *options]) == (0 if mode == "dry" else 2)
    output = json.loads(capsys.readouterr().out)
    assert output["assessment_outcome"] == "inconclusive"
    assert len(backend_double) == executions
    assert output["broker"]["calls_reserved"] == proposals
    report = inspect_assessment(tmp_path / "evidence")
    assert report["integrity_issues"] == []
    assert report["terminal_decision"]["reason"] == reason
    assert len(report["records"]) == executions
    if proposals > executions:
        assert report["decision_trace"][executions]["execution_status"] == "not_executed"
        assert report["decision_trace"][executions]["execution_id"] is None
    if mode == "dry":
        assert report["decision_trace"][-1]["reason"] == "predecessor_evidence_missing"


@pytest.mark.parametrize("limits,expected", [
    (BrokerLimits(max_calls=1), "broker_call_limit"),
    (BrokerLimits(max_reserved_output_tokens=1024), "broker_token_limit"),
    (BrokerLimits(max_request_bytes=1), "broker_request_limit"),
])
def test_broker_budget_failure_retains_decision_without_authorizing_execution(provider_case, monkeypatch, limits, expected):
    case = provider_case
    observation = finish_first(case) if expected != "broker_request_limit" else _observation(1, None)
    monkeypatch.setattr(case.provider.broker, "_limits", limits)
    with pytest.raises(ExecutionStopped, match=expected):
        case.provider.propose(observation, control=case.control)
    assert journal(case.directory)[-1]["event_type"] == "assessment_workflow_decision"
    steps = 2 if expected != "broker_request_limit" else 1
    terminal = workflow.terminal_decision("a", case.evidence.records, {
        "steps_attempted": steps, "session_status": "stopped", "stop_reason": expected, "mode": "execute"})
    assert terminal.reason == expected and terminal.action is None
    assert len(case.evidence.records) == steps - 1
    assert case.provider.broker.snapshot["calls_reserved"] == steps - 1


@pytest.mark.parametrize("extra", [["--routed"], ["--openai-model", "other"], ["--broker-max-calls", "3"],
                                   ["--discovery-assessment", "a"], ["--live"]])
def test_incompatible_cli_options_fail_before_creating_evidence(tmp_path, monkeypatch, extra):
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("policy must not be read"))
    with pytest.raises(SystemExit) as error:
        cli.main([*arguments(tmp_path, execute=False), *extra])
    assert error.value.code == 2 and not (tmp_path / "evidence").exists()
