"""Opt-in disconnected native routing; no target, credential or provider inputs."""
import json
import os
from pathlib import Path
import sys
import subprocess

import pytest

from recon_cockpit.secure_agent import routing as diagnostic, routing_contract as contract

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def owned_only():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned disconnected routing")
    assert sys.platform == "linux" and os.geteuid() != 0


@pytest.fixture
def diagnostics(monkeypatch, tmp_path):
    from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
    original = LinuxFixtureLauncher._cleanup
    def cleanup(self):
        try:
            return original(self)
        finally:
            if self._supervisor is not None:
                rows = {key: bytes(value).decode("utf-8", "replace") for key, value in self._supervisor.buffers.items()}
                (tmp_path / "launcher-diagnostics.json").write_text(json.dumps(rows, sort_keys=True))
    monkeypatch.setattr(LinuxFixtureLauncher, "_cleanup", cleanup)
    return tmp_path / "launcher-diagnostics.json"


def trial(tmp_path, monkeypatch, diagnostics, selectors, budget_case="ordinary", require_approval=False,
          deployment=None, case_profile=None):
    from recon_cockpit.secure_agent.routing_lab import RoutingLab
    from recon_cockpit.secure_agent.routing_backend import AuthorizedRoutingBackend
    from recon_cockpit.secure_agent.routing_evidence import inspect_trial
    monkeypatch.setattr(RoutingLab, "start", lambda *args: pytest.fail("host owner fallback"))
    monkeypatch.setattr(AuthorizedRoutingBackend, "run", lambda *args, **kw: pytest.fail("host execution fallback"))
    directory = tmp_path / "trial"
    try:
        report = diagnostic.run_trial(directory, selectors=selectors, budget_case=budget_case,
            deployment=deployment, case_profile=case_profile,
            execute=True, unattended_owned_lab_test=not require_approval)
    except Exception:
        if diagnostics.exists(): print(diagnostics.read_text())
        raise
    if not report["case_passed"] and diagnostics.exists(): print(diagnostics.read_text())
    before = {path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns) for path in directory.iterdir()}
    assert inspect_trial(directory) == report
    replay = subprocess.run([sys.executable, "scripts/disconnected_routing.py", "inspect", str(directory)],
                            capture_output=True, timeout=45, check=False)
    assert replay.returncode == (0 if report["case_passed"] else 1), replay.stderr.decode("utf-8", "replace")
    assert json.loads(replay.stdout) == report
    assert before == {path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns) for path in directory.iterdir()}
    assert report["metrics"]["actual_provider_calls"] == report["metrics"]["actual_cost_microusd"] == 0
    assert report["closure"]["launcher_cleanup_verified"] is True
    return report, directory


@pytest.mark.parametrize("selectors", [[name] for name in contract.SELECTORS] + [list(contract.SELECTORS), list(reversed(contract.SELECTORS))],
                         ids=[*contract.SELECTORS, "four-explicit-actions", "reverse-explicit-order"])
def test_native_independent_actions_share_one_routed_budget(tmp_path, monkeypatch, diagnostics, record_property, selectors):
    report, directory = trial(tmp_path, monkeypatch, diagnostics, selectors)
    assert report["case_passed"] is True, report
    assert report["classification"] == "completed"
    assert report["metrics"]["legitimate_task_completed"] is True
    assert report["metrics"]["useful_actions_completed"] == len(selectors)
    assert report["metrics"]["unnecessary_refusals"] == 0
    assert report["metrics"]["excluded_destination_probes_blocked"] == 8
    assert report["metrics"]["reservations"]["actions"] == len(selectors)
    metadata = []
    for step, selector in enumerate(selectors, 1):
        result = json.loads((directory / f"result-{step}.json").read_bytes())
        assert result["routing_service"]["selector"] == selector
        assert all(value is True for value in result["boundary_checks"].values())
        assert result["routing_service"]["closure"]["daemon_processes_reaped"] is True
        metadata.append(result["routing_topology"])
    assert all(value == metadata[0] for value in metadata)
    record_property("case_passed", True)
    record_property("useful_actions_completed", len(selectors))
    record_property("actual_provider_calls", 0)


@pytest.mark.parametrize("budget_case,selectors,limit", [
    ("connection_one", ["http_headers", "ssh_keys"], "connections"),
    ("http_one", ["http_headers", "http_nmap"], "http_requests"),
    ("ssh_zero", ["http_headers", "ssh_keys"], "kex_exchanges"),
])
def test_native_aggregate_denial_preserves_completed_work(tmp_path, monkeypatch, diagnostics, record_property, budget_case, selectors, limit):
    report, directory = trial(tmp_path, monkeypatch, diagnostics, selectors, budget_case)
    assert report["case_passed"] is True, report
    assert report["classification"] == "expected_budget_refusal"
    assert report["metrics"]["useful_actions_completed"] == 1
    assert report["metrics"]["legitimate_task_completed"] is False
    assert report["metrics"]["expected_negative"] is True
    assert report["metrics"]["reservations"][limit] == contract.budgets(contract.selection(budget_case))[limit]
    result = json.loads((directory / "result-2.json").read_bytes())
    assert result["routing_ledger"]["terminal_reason"] == "aggregate_" + limit + "_limit"
    assert result["tool_observation"] is None
    assert result["routing_service"]["budget_denied"] is True
    record_property("case_passed", True)
    record_property("useful_actions_completed", 1)
    record_property("actual_provider_calls", 0)


def test_native_default_approval_policy_cannot_launch_unattended(tmp_path, monkeypatch, diagnostics):
    report, directory = trial(tmp_path, monkeypatch, diagnostics, ["http_headers"], require_approval=True)
    assert report["case_passed"] is False
    assert report["actions"][0]["execution_status"] == "blocked"
    assert report["metrics"]["reservations"] is None
    assert report["closure"]["connection_count"] == 0
    assert not (directory / "result-1.json").exists()
