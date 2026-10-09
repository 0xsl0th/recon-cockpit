"""Direct application entry, state custody and lifecycle without OS acceptance.

Portable doubles retain the existing authority flow but make no kernel isolation
or personal-approval claim. Actual execution is covered by the Linux companion.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import threading

import pytest

from recon_cockpit.secure_agent import configurable_service as application
from recon_cockpit.secure_agent.configurable_evidence import inspect_assessment
from recon_cockpit.secure_agent.execution import ExecutionStopped
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_secure_http_headers_cli import portable_services


def request(tmp_path, **changes):
    values = {"scope_json": Path("examples/secure-agent-configurable-scope.json").read_bytes(),
        "policy_json": Path("examples/secure-agent-configurable-policy.json").read_bytes(),
        "assessment_dir": tmp_path / "evidence", "audit_path": tmp_path / "audit.jsonl"}
    values.update(changes)
    return application.ConfigurableAssessmentRequest(**values)


@pytest.mark.parametrize("changes", [
    {"scope_json": b"{}"}, {"scope_json": b"x" * 4097}, {"scope_json": "{}"},
    {"policy_json": b"{}"}, {"policy_json": b"x" * 16385}, {"policy_json": "{}"},
    {"execute": 1}, {"execute": None}, {"limits": {}},
    {"limits": SessionLimits(5, 60, 26624)},
    {"limits": SessionLimits(4, 61, 26624)},
    {"limits": SessionLimits(4, 60, 26625)},
    {"assessment_dir": "evidence"}, {"audit_path": "audit.jsonl"},
])
def test_invalid_direct_request_is_rejected_before_filesystem_effects(tmp_path, changes):
    with pytest.raises(ValueError):
        request(tmp_path, **changes)
    assert not list(tmp_path.iterdir())


def test_request_retains_only_canonical_immutable_inputs_and_shortened_limits(tmp_path):
    limits = SessionLimits(2, 15, 10240)
    original = request(tmp_path, limits=limits)
    assert original.limits == limits and original.limits is not limits
    for raw in (original.scope_json, original.policy_json):
        assert type(raw) is bytes
        assert raw == json.dumps(json.loads(raw), sort_keys=True, ensure_ascii=True,
                                 separators=(",", ":"), allow_nan=False).encode("ascii")
    with pytest.raises(FrozenInstanceError):
        original.execute = True
    with pytest.raises(FrozenInstanceError):
        original.limits.max_steps = 4
    assert not list(tmp_path.iterdir())


def test_new_service_is_read_only_and_snapshot_is_detached(tmp_path):
    service = application.ConfigurableAssessmentService(request(tmp_path))
    first = service.snapshot()
    assert first["state"] == "ready" and first["result"] is None and first["steps"] == []
    assert first["stop_reason"] is None and first["live_calls_enabled"] is False
    original = service.snapshot()
    first["scope"]["http"]["target"] = "8.8.8.8"
    first["steps"].append({"decision": "allow"})
    assert service.snapshot() == original
    assert not list(tmp_path.iterdir())


def test_cannot_construct_from_a_serialized_snapshot(tmp_path):
    view = application.ConfigurableAssessmentService(request(tmp_path)).snapshot()
    with pytest.raises(ValueError, match="invalid_assessment_request"):
        application.ConfigurableAssessmentService(view)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("kwargs", [{"interactive_terminal": 1}, {"on_step": {}}])
def test_invalid_run_options_never_enter_services(tmp_path, monkeypatch, kwargs):
    from recon_cockpit.secure_agent import audit_isolation
    monkeypatch.setattr(audit_isolation, "LinuxAuditSink", lambda *a, **k: pytest.fail("audit opened"))
    service = application.ConfigurableAssessmentService(request(tmp_path))
    with pytest.raises(ValueError):
        service.run(**kwargs)
    assert service.snapshot()["state"] == "ready" and not list(tmp_path.iterdir())


def test_direct_dry_run_owns_mandatory_gates_and_replays_readonly(
        tmp_path, monkeypatch, portable_services):
    from recon_cockpit.secure_agent import (audit_isolation, approval_isolation,
        launcher_isolation, configurable_runtime, configurable_parser_runtime)
    constructors = []
    for module, name in ((audit_isolation, "LinuxAuditSink"),
                         (approval_isolation, "LinuxApprovalService"),
                         (launcher_isolation, "LinuxFixtureLauncher")):
        kind = getattr(module, name)
        original = kind.__init__

        def make(instance, *args, _original=original, _name=name, **kwargs):
            constructors.append((_name, dict(kwargs)))
            _original(instance, *args, **kwargs)

        monkeypatch.setattr(kind, "__init__", make)
    monkeypatch.setattr(configurable_runtime, "inspect_configurable_runtime",
                        lambda *_: pytest.fail("dry runtime inspection"))
    monkeypatch.setattr(configurable_parser_runtime, "parse_isolated_tool_output",
                        lambda *a, **k: pytest.fail("dry tool parsing"))
    service = application.ConfigurableAssessmentService(request(tmp_path))
    seen = []
    result = service.run(on_step=seen.append)
    assert result["assessment_outcome"] == "dry_run"
    assert result["actions_succeeded"] == 0
    assert result["metrics"]["legitimate_task_completed"] is False
    assert result["metrics"]["actual_provider_calls"] == result["metrics"]["actual_cost_microusd"] == 0
    assert [name for name, _ in constructors] == ["LinuxAuditSink", "LinuxApprovalService", "LinuxFixtureLauncher"]
    assert constructors[0][1] == constructors[1][1] == {"launch_witness": True}
    assert set(constructors[2][1]) == {"audit", "approvals"}
    view = service.snapshot()
    assert view["state"] == "finished" and view["result"] == result and view["steps"] == seen
    assert view["stop_reason"] == result["stop_reason"]
    assert not any(row["event_type"] == "execution_started" for row in portable_services)
    directory = tmp_path / "evidence"
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in directory.iterdir()}
    assert inspect_assessment(directory)["integrity_issues"] == []
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in directory.iterdir()}


def test_observer_return_and_snapshot_mutation_cannot_change_retained_summary(
        tmp_path, portable_services):
    service = application.ConfigurableAssessmentService(request(tmp_path))

    def mutate(step):
        step["reasons"].append("forged_ui_reason")
        step["result_metadata"] = {"forged": True}
        step["decision"] = "forged"

    result = service.run(on_step=mutate)
    original = service.snapshot()
    assert "forged" not in json.dumps(original)
    report = json.loads((tmp_path / "evidence" / "report.json").read_text())
    assert original["steps"] == result["steps"]
    assert "forged" not in json.dumps(report)
    result["steps"][0]["reasons"].append("mutated return")
    result["capability"]["scope"]["http"]["target"] = "8.8.8.8"
    view = service.snapshot()
    view["steps"][0]["reasons"].append("mutated view")
    view["result"]["metrics"]["legitimate_task_completed"] = True
    assert service.snapshot() == original


def test_direct_run_works_in_a_worker_thread_without_signal_handlers(tmp_path, portable_services):
    service = application.ConfigurableAssessmentService(request(tmp_path))
    threads = []
    with ThreadPoolExecutor(max_workers=1) as pool:
        result = pool.submit(service.run, on_step=lambda _: threads.append(threading.get_ident())).result(timeout=10)
    assert result["assessment_outcome"] == "dry_run"
    assert threads and all(identifier != threading.get_ident() for identifier in threads)


def test_finished_session_is_not_reusable_and_preserves_final_view(tmp_path, portable_services):
    service = application.ConfigurableAssessmentService(request(tmp_path))
    service.run()
    expected = service.snapshot()
    with pytest.raises(RuntimeError, match="assessment_already_used"):
        service.run()
    service.cancel()
    assert service.snapshot() == expected


def test_cancellation_before_start_opens_nothing_and_is_terminal(tmp_path, monkeypatch):
    from recon_cockpit.secure_agent import audit_isolation, configurable_runtime
    monkeypatch.setattr(audit_isolation, "LinuxAuditSink", lambda *a, **k: pytest.fail("audit opened"))
    monkeypatch.setattr(configurable_runtime, "inspect_configurable_runtime",
                        lambda *_: pytest.fail("runtime inspected"))
    service = application.ConfigurableAssessmentService(request(tmp_path, execute=True))
    service.cancel()
    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        service.run()
    assert service.snapshot()["state"] == "stopped"
    assert service.snapshot()["stop_reason"] == "session_cancelled"
    assert service.snapshot()["result"] is None
    with pytest.raises(RuntimeError, match="assessment_already_used"):
        service.run()
    assert not list(tmp_path.iterdir())


def test_runtime_inspection_receives_same_cancellation_event(tmp_path, monkeypatch):
    from recon_cockpit.secure_agent import audit_isolation, configurable_runtime
    service = application.ConfigurableAssessmentService(request(tmp_path, execute=True))

    def inspect(control):
        control.check()
        service.cancel()
        control.check()

    monkeypatch.setattr(configurable_runtime, "inspect_configurable_runtime", inspect)
    monkeypatch.setattr(audit_isolation, "LinuxAuditSink", lambda *a, **k: pytest.fail("audit opened"))
    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        service.run()
    assert service.snapshot()["state"] == "stopped" and not list(tmp_path.iterdir())


def test_setup_cancellation_closes_audit_before_creating_approvals(tmp_path, monkeypatch, portable_services):
    from recon_cockpit.secure_agent import audit_isolation, approval_isolation
    service = application.ConfigurableAssessmentService(request(tmp_path))
    original = audit_isolation.LinuxAuditSink
    opened = []

    def audit(*args, **kwargs):
        instance = original(*args, **kwargs)
        opened.append(instance)
        service.cancel()
        return instance

    monkeypatch.setattr(audit_isolation, "LinuxAuditSink", audit)
    monkeypatch.setattr(approval_isolation, "LinuxApprovalService",
                        lambda *a, **k: pytest.fail("approval service opened after cancellation"))
    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        service.run()
    assert opened[0]._closed
    assert service.snapshot()["stop_reason"] == "session_cancelled"
    assert not (tmp_path / "evidence").exists()


def test_cancellation_during_evidence_setup_reaches_new_runner(tmp_path, monkeypatch, portable_services):
    from recon_cockpit.secure_agent import configurable_evidence
    service = application.ConfigurableAssessmentService(request(tmp_path))
    original = configurable_evidence.ConfigurableEvidenceStore.__init__

    def start(store, *args, **kwargs):
        original(store, *args, **kwargs)
        service.cancel()

    monkeypatch.setattr(configurable_evidence.ConfigurableEvidenceStore, "__init__", start)
    result = service.run()
    assert result["stop_reason"] == "session_cancelled"
    assert result["steps_attempted"] == result["actions_succeeded"] == 0
    assert service.snapshot()["stop_reason"] == "session_cancelled"
    report = inspect_assessment(tmp_path / "evidence")
    assert report["integrity_issues"] == [] and report["lab_closure"]["status"] == "closed"


def test_concurrent_start_is_rejected_and_cancel_cannot_be_lost(tmp_path, monkeypatch, portable_services):
    from recon_cockpit.secure_agent import audit_isolation
    service = application.ConfigurableAssessmentService(request(tmp_path))
    original = audit_isolation.LinuxAuditSink
    entered, release = threading.Event(), threading.Event()

    def audit(*args, **kwargs):
        instance = original(*args, **kwargs)
        entered.set()
        assert release.wait(5)
        return instance

    monkeypatch.setattr(audit_isolation, "LinuxAuditSink", audit)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(service.run)
        try:
            assert entered.wait(5)
            assert service.snapshot()["state"] == "running"
            with pytest.raises(RuntimeError, match="assessment_already_running"):
                service.run()
            service.cancel()
        finally:
            release.set()
        with pytest.raises(ExecutionStopped, match="session_cancelled"):
            future.result(timeout=5)
    assert service.snapshot()["state"] == "stopped"


@pytest.mark.parametrize("error_type", (RuntimeError, ValueError, OSError, KeyboardInterrupt))
def test_observer_error_closes_all_services_without_claiming_a_report(
        tmp_path, monkeypatch, portable_services, error_type):
    from recon_cockpit.secure_agent import audit_isolation, approval_isolation, launcher_isolation
    service = application.ConfigurableAssessmentService(request(tmp_path))
    objects = []
    for module, name in ((audit_isolation, "LinuxAuditSink"),
                         (approval_isolation, "LinuxApprovalService"),
                         (launcher_isolation, "LinuxFixtureLauncher")):
        kind = getattr(module, name)
        original = kind.__init__

        def make(instance, *args, _original=original, **kwargs):
            _original(instance, *args, **kwargs)
            objects.append(instance)

        monkeypatch.setattr(kind, "__init__", make)

    def stop(_):
        raise error_type("observer failed")

    with pytest.raises(error_type, match="observer failed"):
        service.run(on_step=stop)
    assert all(instance._closed for instance in objects)
    view = service.snapshot()
    assert view["state"] == "failed" and view["stop_reason"] == "assessment_failed"
    assert view["result"] is None and not (tmp_path / "evidence" / "report.json").exists()
    assert inspect_assessment(tmp_path / "evidence")["integrity_issues"]
    with pytest.raises(RuntimeError, match="assessment_already_used"):
        service.run()
