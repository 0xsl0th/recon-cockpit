"""Default and maximum batches replay beyond the generic JSON input limit."""

from copy import deepcopy
import json

import pytest

from recon_cockpit.secure_agent.evaluation import EvaluationLimits
from recon_cockpit.secure_agent.planning_evaluation import PlanningEvaluationRunner, inspect_planning_evaluation
from recon_cockpit.secure_agent.planning_evaluation_contract import TRIAL_BUDGET
from test_secure_evaluation import boundaries, policy, snapshot
from test_secure_planning_evaluation_grading import planning_boundaries


@pytest.mark.parametrize("repeats", [3, 10], ids=["default-eighteen", "maximum-sixty"])
def test_complete_large_batches_replay_all_costs_without_parsing_cached_claims(
        tmp_path, planning_boundaries, repeats):
    directory = tmp_path / "batch"
    runner = PlanningEvaluationRunner(directory, policy(), EvaluationLimits(repeats=repeats))
    report = runner.run(execute=True)
    assert report["status"] == "passed" and report["integrity_issues"] == []
    assert report["started_trials"] == report["completed_trials"] == report["passed_trials"] == repeats * 6
    assert report["resource_accounting_complete"] is True
    assert report["correct_abstentions"] == repeats * 4
    assert all(item["semantic_agreement"] for item in report["per_case"])
    metrics = report["aggregate_metrics"]
    assert metrics["owned_tls_exchanges"] == metrics["executions"] == repeats * 17
    assert metrics["actions_succeeded"] == repeats * 15
    assert metrics["planning_actual_microusd"] == repeats * 17 * 778
    assert metrics["planning_input_tokens"] == repeats * 17 * 512
    assert metrics["planning_output_tokens"] == repeats * 17 * 128
    assert metrics["planning_reserved_microusd"] == metrics["planning_unresolved_attempts"] == 0
    assert metrics["actual_provider_calls"] == metrics["unnecessary_actions"] == 0
    assert report["planning_cost"]["summary"]["limit_microusd"] == repeats * 6 * TRIAL_BUDGET
    assert report["planning_cost"]["summary"]["actual_microusd"] == repeats * 17 * 778
    assert report["planning_cost"]["summary"]["actual_complete"] is True
    assert all(all(trial["grade"]["checks"].values()) for trial in report["trials"])
    for key in ("assessment_id", "session_id", "lab_instance_id", "broker_id",
                "session_scope_id", "agent_scope_id", "action_scope_id"):
        assert len({trial["grade"][key] for trial in report["trials"]}) == repeats * 6
    for case in "abcdef":
        fingerprints = {trial["grade"]["semantic_fingerprint"] for trial in report["trials"] if trial["case"] == case}
        assert len(fingerprints) == 1 and None not in fingerprints

    path = directory / "report.json"
    original = path.read_bytes()
    assert len(original) > 32768
    before = snapshot(directory)
    assert inspect_planning_evaluation(directory) == report
    assert snapshot(directory) == before

    # Cached claims never become input to grading. A semantically changed
    # document and a noncanonical serialization are both rejected as caches.
    changed = deepcopy(report)
    changed["planning_cost"]["summary"]["actual_microusd"] = 0
    for raw in (json.dumps(changed).encode(), original + b"\n"):
        path.write_bytes(raw)
        before = snapshot(directory)
        actual = inspect_planning_evaluation(directory)
        assert actual["status"] == "failed"
        assert "aggregate_report_mismatch" in actual["integrity_issues"]
        assert actual["planning_cost"]["summary"]["actual_microusd"] == repeats * 17 * 778
        assert actual["aggregate_metrics"] == metrics
        assert snapshot(directory) == before
    path.write_bytes(original)
    assert inspect_planning_evaluation(directory) == report
