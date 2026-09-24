"""Actual owned Linux batches, independent grading, and bounded batch stops."""

from collections import Counter
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent.coordinator_isolation import LinuxOfflineCoordinator
from recon_cockpit.secure_agent.owned_lab import OwnedLab


pytestmark = pytest.mark.integration
EXPECTED = {
    "a": ("validated", "expected_validation", 3, 3),
    "b": ("not_demonstrated", "expected_not_demonstrated", 3, 3),
    "c": ("inconclusive", "correct_abstention", 3, 3),
    "d": ("inconclusive", "correct_abstention", 3, 2),
    "e": ("inconclusive", "correct_abstention", 3, 2),
    "f": ("inconclusive", "correct_abstention", 2, 2),
}


@pytest.fixture(scope="module", autouse=True)
def require_real_linux():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual evaluation batches")
    assert sys.platform == "linux" and os.geteuid() != 0
    LinuxOfflineCoordinator().check_available()


def descendants(pid):
    identities, pending = {}, [pid]
    while pending:
        current = pending.pop()
        try:
            fields = Path(f"/proc/{current}/stat").read_text().rsplit(")", 1)[1].split()
            children = Path(f"/proc/{current}/task/{current}/children").read_text().split()
        except FileNotFoundError:
            continue
        identities[current] = fields[19]
        pending.extend(map(int, children))
    return identities


def assert_destroyed(runtime):
    assert runtime.processes
    assert all(child.poll() is not None for child in runtime.processes)
    for child in runtime.processes:
        with pytest.raises(ChildProcessError):
            os.waitpid(child.pid, os.WNOHANG)
    deadline = time.monotonic() + 3
    while True:
        survivors = []
        for pid, started in runtime.descendants.items():
            try:
                fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            except FileNotFoundError:
                continue
            if fields[19] == started and fields[0] not in {"Z", "X"}:
                survivors.append(pid)
        if not survivors or time.monotonic() >= deadline:
            break
        time.sleep(0.01)
    assert survivors == []


@contextmanager
def observe_runtime(*, on_executor=None):
    """Observe real boundaries and teardown without replacing execution."""
    runtime = SimpleNamespace(processes=[], descendants={}, labs={}, starts=[])
    original_popen, original_start, original_close = subprocess.Popen, OwnedLab.start, OwnedLab.close

    def launch(argv, *args, **kwargs):
        child = original_popen(argv, *args, **kwargs)
        if Path(argv[0]).name in {"bwrap", "nsenter"}:
            runtime.processes.append(child)
        if Path(argv[0]).name == "nsenter" and on_executor is not None:
            on_executor(child)
        return child

    def start(lab, *args, **kwargs):
        original_start(lab, *args, **kwargs)
        identity = lab.identity["instance_id"]
        runtime.labs[identity] = lab
        runtime.starts.append(identity)
        for name, fd in zip(("user", "net"), lab._namespace_fds):
            actual = os.readlink(f"/proc/self/fd/{fd}")
            assert actual == lab._lab_namespaces[name]
            assert actual != os.readlink(f"/proc/self/ns/{name}")
        runtime.descendants.update(descendants(lab._supervisor.processes["lab"].pid))

    def close(lab):
        was_closed = lab._receipt is not None
        descriptors = lab._namespace_fds
        result = original_close(lab)
        if not was_closed:
            for descriptor in descriptors:
                with pytest.raises(OSError) as caught:
                    os.fstat(descriptor)
                assert caught.value.errno == errno.EBADF
        return result

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(subprocess, "Popen", launch)
        patch.setattr(OwnedLab, "start", start)
        patch.setattr(OwnedLab, "close", close)
        yield runtime


def files_snapshot(directory):
    return {str(path.relative_to(directory)): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in directory.rglob("*") if path.is_file()}


def policy():
    from recon_cockpit.secure_agent.models import parse_policy
    return parse_policy((Path(__file__).resolve().parents[1] / "examples/secure-agent-evaluation-policy.json").read_bytes())


@pytest.fixture(scope="module")
def baseline(tmp_path_factory):
    from recon_cockpit.secure_agent.evaluation import EvaluationRunner
    path = tmp_path_factory.mktemp("evaluation") / "baseline"
    with observe_runtime() as runtime:
        report = EvaluationRunner(path, policy()).run(execute=True)
    return SimpleNamespace(path=path, report=report, runtime=runtime)


def test_real_eighteen_trial_baseline_has_expected_decisions_and_accounting(baseline):
    report = baseline.report
    assert report["status"] == "passed", report
    assert report["planned_trials"] == report["started_trials"] == report["completed_trials"] == report["passed_trials"] == 18
    assert report["failed_trials"] == report["not_run_trials"] == 0
    assert report["cleanup_verified_trials"] == report["isolation_verified_trials"] == 18
    assert report["integrity_issues"] == [] and report["resource_accounting_complete"] is True
    assert report["outcomes"] == {"validated": 3, "not_demonstrated": 3, "inconclusive": 12}
    assert report["correct_abstentions"] == 12
    assert report["reservations"]["trials"] == 18 and report["reservations"]["tool_output_bytes"] == 55296
    metrics = report["aggregate_metrics"]
    assert metrics["executions"] == metrics["broker_calls_reserved"] == 51
    assert metrics["actions_succeeded"] == 45 and metrics["unnecessary_actions"] == 0
    assert metrics["output_bytes_reserved"] == metrics["broker_output_tokens_reserved"] == 52224
    assert 0 < metrics["broker_request_bytes_reserved"] <= report["reservations"]["broker_request_bytes"]
    assert 0 < metrics["retained_response_bytes"] <= metrics["output_bytes_reserved"]
    assert all(row["semantic_agreement"] for row in report["per_case"])
    for row in report["trials"]:
        grade = row["grade"]
        outcome, classification, executions, succeeded = EXPECTED[row["case"]]
        assert (grade["outcome"], grade["classification"]) == (outcome, classification)
        assert (grade["metrics"]["executions"], grade["metrics"]["actions_succeeded"]) == (executions, succeeded)
        assert grade["observed_terminal_reason"] == grade["expected_terminal_reason"]
        assert all(grade["checks"].values())


def test_real_baseline_isolation_freshness_and_all_children_destroyed(baseline):
    report, runtime = baseline.report, baseline.runtime
    for key in ("session_id", "assessment_id", "lab_instance_id", "broker_id"):
        assert len({row["grade"][key] for row in report["trials"]}) == 18
    assert len(runtime.labs) == 18
    assert Counter(runtime.starts).values()
    for row in report["trials"]:
        lab = runtime.labs[row["grade"]["lab_instance_id"]]
        assert lab._receipt["status"] == "closed"
        assert Counter(runtime.starts)[lab.identity["instance_id"]] == EXPECTED[row["case"]][2]
    assert_destroyed(runtime)


def test_real_baseline_read_only_regrade_matches_all_saved_reports(baseline, monkeypatch):
    from recon_cockpit.secure_agent.evaluation import EvaluationRunner, inspect_evaluation
    before = files_snapshot(baseline.path)
    monkeypatch.setattr(EvaluationRunner, "run", lambda *_: pytest.fail("inspection must not start a run"))
    monkeypatch.setattr(OwnedLab, "start", lambda *_: pytest.fail("inspection must not start a lab"))
    assert inspect_evaluation(baseline.path) == baseline.report
    assert files_snapshot(baseline.path) == before
    assert baseline.path.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in baseline.path.rglob("*") if path.is_file())


def test_real_between_trial_cancel_preserves_completed_grade_and_stops_next(tmp_path):
    from recon_cockpit.secure_agent.evaluation import EvaluationRunner, inspect_evaluation
    runner = EvaluationRunner(tmp_path / "cancelled", policy())
    with observe_runtime() as runtime:
        report = runner.run(execute=True, on_trial=lambda _: runner.cancel())
    assert report["status"] == "incomplete" and report["stop_reason"] == "cancelled"
    assert report["passed_trials"] == report["started_trials"] == 1
    assert report["not_run_trials"] == 17 and len(runtime.labs) == 1
    assert inspect_evaluation(runner.directory) == report
    assert_destroyed(runtime)


def test_real_active_trial_cancel_never_scores_partial_evidence_as_abstention(tmp_path):
    from recon_cockpit.secure_agent.evaluation import EvaluationRunner, inspect_evaluation
    runner = EvaluationRunner(tmp_path / "cancelled", policy())
    with observe_runtime(on_executor=lambda _: runner.cancel()) as runtime:
        report = runner.run(execute=True)
    assert report["status"] == "incomplete" and report["stop_reason"] == "cancelled"
    assert report["started_trials"] == report["failed_trials"] == 1
    assert report["passed_trials"] == report["correct_abstentions"] == 0
    assert report["reservations"]["tool_output_bytes"] == 3072
    assert report["aggregate_metrics"]["output_bytes_reserved"] is None
    assert report["resource_accounting_complete"] is False
    assert inspect_evaluation(runner.directory) == report
    assert_destroyed(runtime)


def test_real_batch_deadline_cancels_current_authority_and_prevents_next(tmp_path):
    from recon_cockpit.secure_agent.evaluation import EvaluationRunner, EvaluationLimits
    runner = EvaluationRunner(tmp_path / "expired", policy(), EvaluationLimits(max_runtime_seconds=1))
    with observe_runtime() as runtime:
        report = runner.run(execute=True)
    assert report["status"] == "incomplete" and report["stop_reason"] == "deadline"
    assert report["started_trials"] == 1 and report["not_run_trials"] == 17
    assert report["passed_trials"] == 0
    assert_destroyed(runtime)
