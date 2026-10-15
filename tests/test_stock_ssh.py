"""One-action service lifecycle plus opt-in authoritative native corpus."""

from copy import deepcopy
import inspect
import json
import os
import subprocess
import sys
import threading
from types import SimpleNamespace
from uuid import uuid4

import pytest

from test_stock_ssh_client import manifests as runtime
from recon_cockpit.secure_agent import stock_ssh as diagnostic
from recon_cockpit.secure_agent import stock_ssh_spec as spec
from recon_cockpit.secure_agent.execution import ExecutionStopped


@pytest.fixture
def portable_services(monkeypatch):
    """Exercise the real Controller, doubling only isolated lifecycle endpoints."""
    calls = []
    monkeypatch.setattr(diagnostic, "inspect_runtime", lambda configuration, case, control: runtime(configuration, case)["daemon"])
    monkeypatch.setattr(diagnostic, "inspect_client_runtime", lambda selected, control: runtime(selected["configuration"], selected["case"])["client"])
    class Evidence:
        def __init__(self, directory, manifest, **options):
            self.manifest = deepcopy(manifest)
            calls.append(("evidence", self.manifest))
        def __enter__(self):
            return self
        def __exit__(self, *_):
            calls.append(("evidence_closed",))
        def start(self, action, policy, **options):
            calls.append(("evidence_started", action.to_dict(), options))
            return str(uuid4())
        def finish(self, *args, **kwargs):
            calls.append(("evidence_finished",))
        def finalize(self, outcome, **kwargs):
            calls.append(("finalized", kwargs))
            return deepcopy(outcome)
    class Audit:
        def __init__(self, path, **options):
            calls.append(("audit", options))
        def __enter__(self):
            return self
        def __exit__(self, *_):
            calls.append(("audit_closed",))
        def emit(self, event):
            calls.append(("event", deepcopy(event)))
    class Approvals:
        def __init__(self, policy, session_id, **options):
            calls.append(("approvals", policy.require_approval, options))
        def __enter__(self):
            return self
        def __exit__(self, *_):
            calls.append(("approvals_closed",))
        def consume(self, *args, **kwargs):
            pytest.fail("noninteractive diagnostics may not fabricate approval")
    class Launcher:
        def __init__(self, original, *, audit, approvals):
            self.name = original.name
            calls.append(("launcher", original.selection, audit, approvals))
        def __enter__(self):
            return self
        def __exit__(self, *_):
            calls.append(("launcher_closed",))
        def check_available(self, action):
            calls.append(("availability", action.to_dict()))
        def run(self, action, policy, **options):
            calls.append(("run", action.to_dict(), policy.to_dict(), options))
            return {"status": "failed"}
    monkeypatch.setattr(diagnostic, "StockSshEvidenceStore", Evidence)
    monkeypatch.setattr(diagnostic, "LinuxAuditSink", Audit)
    monkeypatch.setattr(diagnostic, "LinuxApprovalService", Approvals)
    monkeypatch.setattr(diagnostic, "LinuxFixtureLauncher", Launcher)
    return calls


def test_default_execute_false_requires_no_backend_run_and_has_witnesses(portable_services, tmp_path):
    report = diagnostic.run_trial(tmp_path / "trial", configuration="A", case="O1")
    calls = portable_services
    assert report["execution_status"] == "dry_run"
    assert not any(row[0] in ("availability", "run") for row in calls)
    assert next(row for row in calls if row[0] == "audit")[1] == {"launch_witness": True}
    approval = next(row for row in calls if row[0] == "approvals")
    assert approval[1] is True and approval[2] == {"launch_witness": True}
    assert [row[0] for row in calls if row[0].endswith("_closed")] == [
        "launcher_closed", "approvals_closed", "audit_closed", "evidence_closed"]


def test_execution_requires_explicit_test_policy_or_real_approval(portable_services, tmp_path):
    report = diagnostic.run_trial(tmp_path / "trial", configuration="A", case="O1", execute=True)
    assert report["execution_status"] == "blocked"
    assert report["reasons"] == ["noninteractive_approval_required"]
    assert not any(row[0] == "run" for row in portable_services)
    events = [row[1]["event_type"] for row in portable_services if row[0] == "event"]
    assert events == ["policy_decision", "approval_rejected"]


def test_explicit_test_policy_keeps_exact_action_and_all_service_witnesses(portable_services, tmp_path):
    report = diagnostic.run_trial(tmp_path / "trial", configuration="B", case="R1",
                                  execute=True, unattended_owned_lab_test=True)
    assert report["execution_status"] == "failed"  # No native result is fabricated by this unit test.
    run = next(row for row in portable_services if row[0] == "run")
    assert run[1] == spec.action("B", "R1") and run[2]["require_approval"] is False
    assert next(row for row in portable_services if row[0] == "approvals")[2] == {"launch_witness": True}
    events = [row[1]["event_type"] for row in portable_services if row[0] == "event"]
    assert events == ["policy_decision", "execution_started", "execution_finished"]
    assert next(index for index, row in enumerate(portable_services) if row[0] == "run") > next(
        index for index, row in enumerate(portable_services)
        if row[0] == "event" and row[1]["event_type"] == "execution_started")


def test_wall_time_includes_preflight_without_shortening_execution_session(portable_services, monkeypatch, tmp_path):
    began = diagnostic.time.monotonic()
    now = [began]
    daemon_inspection, client_inspection = diagnostic.inspect_runtime, diagnostic.inspect_client_runtime
    def inspect_daemon(configuration, case, control):
        assert control.deadline == began + 60
        now[0] += 5
        return daemon_inspection(configuration, case, control)
    def inspect_client(selected, control):
        assert control.deadline == began + 60
        now[0] += 2
        return client_inspection(selected, control)
    monkeypatch.setattr(diagnostic, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(diagnostic, "inspect_runtime", inspect_daemon)
    monkeypatch.setattr(diagnostic, "inspect_client_runtime", inspect_client)
    diagnostic.run_trial(tmp_path / "trial", configuration="A", case="O1", execute=True,
                         unattended_owned_lab_test=True)
    run = next(row for row in portable_services if row[0] == "run")
    assert run[3]["control"].deadline == began + 7 + 60
    assert next(row for row in portable_services if row[0] == "finalized")[1] == {"elapsed_ms": 7000}


@pytest.mark.parametrize("options", [
    {"configuration": "host", "case": "O1"}, {"configuration": "A", "case": "arbitrary"},
    {"configuration": "A", "case": "O1", "execute": 1},
    {"configuration": "A", "case": "O1", "unattended_owned_lab_test": "yes"},
    {"configuration": "A", "case": "O1", "cancelled": object()},
])
def test_invalid_selection_or_control_refuses_before_preflight(monkeypatch, tmp_path, options):
    monkeypatch.setattr(diagnostic, "inspect_runtime", lambda *args: pytest.fail("invalid request reached preflight"))
    with pytest.raises(ValueError):
        diagnostic.run_trial(tmp_path / "trial", **options)
    assert not (tmp_path / "trial").exists()


def test_pre_cancelled_session_never_inspects_or_constructs_authority(monkeypatch, tmp_path):
    cancelled = threading.Event()
    cancelled.set()
    def inspect_runtime(configuration, case, control):
        control.check()
        pytest.fail("cancelled request reached filesystem inspection")
    monkeypatch.setattr(diagnostic, "inspect_runtime", inspect_runtime)
    monkeypatch.setattr(diagnostic, "LinuxAuditSink", lambda *args, **kwargs: pytest.fail("cancelled request created authority"))
    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        diagnostic.run_trial(tmp_path / "trial", configuration="A", case="O1", execute=True,
                             unattended_owned_lab_test=True, cancelled=cancelled)
    assert not (tmp_path / "trial").exists()


def test_diagnostic_api_has_no_provider_credentials_or_arbitrary_target_parameters():
    assert tuple(inspect.signature(diagnostic.run_trial).parameters) == (
        "directory", "configuration", "case", "execute", "unattended_owned_lab_test", "cancelled")


def _snapshot(directory):
    return {path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
            for path in directory.iterdir()}


@pytest.mark.integration
@pytest.mark.parametrize("configuration,case", spec.TRIALS, ids=[f"{a}-{b}" for a, b in spec.TRIALS])
def test_authoritative_stock_ssh_corpus_and_unchanged_inspection(tmp_path, monkeypatch, record_property, configuration, case):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for the disconnected stock SSH corpus")
    assert sys.platform == "linux" and os.geteuid() != 0
    from recon_cockpit.secure_agent.stock_ssh_backend import AuthorizedStockSshBackend
    from recon_cockpit.secure_agent.stock_ssh_lab import StockSshLab
    from recon_cockpit.secure_agent.stock_ssh_evidence import inspect_trial
    monkeypatch.setattr(StockSshLab, "start", lambda *args: pytest.fail("host owner fallback"))
    monkeypatch.setattr(AuthorizedStockSshBackend, "run", lambda *args, **kwargs: pytest.fail("host tool fallback"))
    directory = tmp_path / f"openssh-{configuration}-{case}"
    report = diagnostic.run_trial(directory, configuration=configuration, case=case,
                                  execute=True, unattended_owned_lab_test=True)
    assert report["case_passed"] is True, report
    assert report["native_response_verified"] is True
    assert report["implementation"] == "openssh"
    assert report["diagnostic_only"] is False and report["disconnected_owned_lab_only"] is True
    assert report["metrics"]["actual_provider_calls"] == report["metrics"]["actual_cost_microusd"] == 0
    assert report["approval_mode"] == "explicit_unattended_owned_lab_test"
    if case in spec.NEGATIVE_CASES:
        assert report["metrics"]["expected_negative"] is True
        assert report["classification"] in spec.expectation(case)["allowed_outcomes"]
    else:
        assert report["metrics"]["useful_completion"] is True
        assert report["metrics"]["unnecessary_refusal"] is False
    result = json.loads((directory / "result.json").read_bytes())
    assert all(value is True for value in result["boundary_checks"].values())
    assert result["stock_ssh_closure"]["processes_reaped"] is True
    assert result["stock_ssh_closure"]["namespace_descriptors_closed"] is True
    assert result["stock_ssh_owner"]["recorder"]["finalized"] is True
    from recon_cockpit.secure_agent.stock_ssh_owner_worker import PRIVATE_WITNESS
    transport = result["stock_ssh_owner"]["owner"]["recorder"]["private_transport"]
    assert transport["setup_exchange_verified"] is True
    assert transport["setup_witness_bytes_each_direction"] == len(PRIVATE_WITNESS)
    before = _snapshot(directory)
    assert inspect_trial(directory) == report
    replay = subprocess.run([sys.executable, "scripts/stock_ssh_compatibility.py", "inspect", str(directory)],
                            capture_output=True, timeout=30, check=True)
    assert json.loads(replay.stdout) == report
    assert _snapshot(directory) == before
    record_property("case_passed", True)
    record_property("actual_provider_calls", 0)
    record_property("actual_cost_microusd", 0)
    record_property("action_elapsed_ms", report["metrics"]["timing"]["action_elapsed_ms"])
