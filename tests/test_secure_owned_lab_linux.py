"""Real Linux witnesses for one owned lab persisting across bounded actions."""

import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from recon_cockpit.secure_agent.assessment import WorkflowAssessmentProvider
from recon_cockpit.secure_agent.audit import AuditSink
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.coordinator_isolation import LinuxOfflineCoordinator
from recon_cockpit.secure_agent.discovery_contract import discovery_action
from recon_cockpit.secure_agent.evidence import EvidenceStore, EvidenceUnavailable, inspect_assessment
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.owned_lab import AuthorizedOwnedLabBackend, OwnedLab
from recon_cockpit.secure_agent.session import SessionLimits
from recon_cockpit.secure_agent.workflow import card_identity


pytestmark = pytest.mark.integration
CHECKS = dict.fromkeys(("forbidden_ip_blocked", "forbidden_port_blocked",
                       "namespace_creation_blocked", "capabilities_dropped"), True)


@pytest.fixture(autouse=True)
def require_real_linux():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual owned lab isolation")
    assert sys.platform == "linux" and os.geteuid() != 0
    LinuxOfflineCoordinator().check_available()


@pytest.fixture
def processes(monkeypatch):
    children = []
    original = subprocess.Popen

    def launch(argv, *args, **kwargs):
        child = original(argv, *args, **kwargs)
        if Path(argv[0]).name in {"bwrap", "nsenter"}:
            children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)
    return children


def build(*, case="a", approval=False, execute=True, limits=None):
    path = Path(__file__).resolve().parents[1] / "examples/secure-agent-discovery-policy.json"
    policy = parse_policy({**json.loads(path.read_text()), "require_approval": approval})
    limits = limits or SessionLimits(max_steps=3, max_output_bytes=3072)
    session_id = str(uuid4())
    lab = OwnedLab(case, session_id, limits, execute=execute)
    backend = AuthorizedOwnedLabBackend(policy, session_id, limits, lab, execute=execute)
    return SimpleNamespace(policy=policy, limits=limits, session_id=session_id,
                           lab=lab, backend=backend, coordinator=LinuxOfflineCoordinator())


def run_workflow(directory, *, case="a", approval=False, execute=True, limits=None,
                 on_step=None, grant=None):
    configured = build(case=case, approval=approval, execute=execute, limits=limits)
    lab, policy = configured.lab, configured.policy
    namespace_history = []
    audit_path = directory / "audit" / "events.jsonl"
    evidence_path = directory / "evidence"

    def observe(step):
        if lab.started:
            namespace_history.append(dict(lab._lab_namespaces))
            assert [os.readlink(f"/proc/self/fd/{fd}") for fd in lab._namespace_fds] == [
                lab._lab_namespaces[name] for name in ("user", "net")]
        if on_step is not None:
            on_step(configured, step)

    with AuditSink(audit_path) as audit, EvidenceStore(
            evidence_path, session_id=configured.session_id, policy=policy, case=case,
            discovery=True, workflow=True, owned_lab=lab.identity) as evidence:
        configured.provider = WorkflowAssessmentProvider(case, audit, evidence)
        configured.runner = AuthoritySession(
            policy, audit, configured.backend, configured.coordinator, configured.limits,
            session_id=configured.session_id, provider=configured.provider, evidence=evidence)
        try:
            summary = configured.runner.run(execute=execute, on_step=observe,
                                             interactive=grant is not None, approval=grant)
        finally:
            started = lab.started
            receipt = lab.close()
        evidence.record_lab_closed(receipt)
        report = evidence.finalize(summary)
    artifacts = [json.loads((evidence_path / row["artifact"]["filename"]).read_text())
                 for row in report["records"]]
    return SimpleNamespace(**vars(configured), summary=summary, report=report,
                           receipt=receipt, artifacts=artifacts, started=started,
                           namespaces=namespace_history, audit_path=audit_path,
                           evidence_path=evidence_path)


def assert_reaped(processes):
    assert processes
    assert all(child.poll() is not None for child in processes)
    for child in processes:
        with pytest.raises(ChildProcessError):
            os.waitpid(child.pid, os.WNOHANG)


def descendants(pid):
    """Capture process start times so a reused PID cannot masquerade as a leak."""
    result = {}
    pending = [pid]
    while pending:
        current = pending.pop()
        try:
            fields = Path(f"/proc/{current}/stat").read_text().rsplit(")", 1)[1].split()
            children = Path(f"/proc/{current}/task/{current}/children").read_text().split()
        except FileNotFoundError:
            continue
        result[current] = fields[19]
        pending.extend(map(int, children))
    return result


def assert_no_survivors(identities):
    deadline = time.monotonic() + 3
    while True:
        live = []
        for pid, started in identities.items():
            try:
                fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            except FileNotFoundError:
                continue
            if fields[19] == started and fields[0] not in {"Z", "X"}:
                live.append(pid)
        if not live or time.monotonic() >= deadline:
            break
        time.sleep(0.01)
    assert live == []


@pytest.mark.parametrize("case,outcome,succeeded,executions", [
    ("a", "validated", 3, 3), ("b", "not_demonstrated", 3, 3),
    ("c", "inconclusive", 3, 3), ("d", "inconclusive", 2, 3),
    ("e", "inconclusive", 2, 3), ("f", "inconclusive", 2, 2),
])
def test_owned_lab_persists_across_real_workflow_actions_and_closes_before_report(
        tmp_path, processes, case, outcome, succeeded, executions):
    result = run_workflow(tmp_path, case=case)
    report = result.report
    assert result.started is True
    assert report["workflow_card"] == card_identity(owned_lab=True)
    assert report["outcome"] == outcome and report["integrity_issues"] == []
    assert result.summary["actions_succeeded"] == succeeded
    assert result.backend.snapshot["executions_reserved"] == executions
    assert result.backend.snapshot["output_bytes_reserved"] == executions * 1024
    identity = result.lab.identity
    assert str(UUID(identity["instance_id"])) == identity["instance_id"]
    assert identity["scenario"] == case
    assert report["owned_lab"] == {"identity": identity, "closure": result.receipt}
    assert result.receipt == {"identity": identity, "status": "closed",
                              "connection_count": executions, "request_count": executions - 1}
    assert result.lab.close() == result.receipt
    assert len(result.artifacts) == executions
    for step, artifact in enumerate(result.artifacts, 1):
        assert artifact["backend"] == result.backend.name
        assert artifact["boundary_checks"] == CHECKS
        assert artifact["owned_lab"] == {
            "identity": identity, "connection_count": step, "request_count": step - 1}
    # Each action observes the same private service namespace. The fixed allow
    # tuple and listening forbidden witnesses are independently checked above.
    assert len(result.namespaces) == executions
    assert all(value == result.namespaces[0] for value in result.namespaces)
    for name in ("user", "net"):
        assert result.namespaces[0][name] != os.readlink(f"/proc/self/ns/{name}")
    assert_reaped(processes)
    events = [json.loads(line) for line in
              (result.evidence_path / "evidence.jsonl").read_text().splitlines()]
    assert events[-1]["event_type"] == "assessment_finished"
    assert any(event["event_type"] == "assessment_owned_lab_closed" for event in events[:-1])
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns)
              for path in result.evidence_path.iterdir()}
    assert inspect_assessment(result.evidence_path) == report
    assert before == {path.name: (path.read_bytes(), path.stat().st_mtime_ns)
                      for path in result.evidence_path.iterdir()}


@pytest.mark.parametrize("mode,reason", [
    ("dry_run", "dry_run_has_no_execution_evidence"),
    ("missing_approval", "noninteractive_approval_required"),
    ("insufficient_budget", "output_limit"),
])
def test_owned_lab_never_starts_before_execution_is_authorized(tmp_path, processes, mode, reason):
    result = run_workflow(
        tmp_path, approval=mode == "missing_approval", execute=mode != "dry_run",
        limits=SessionLimits(max_output_bytes=1 if mode == "insufficient_budget" else 3072))
    assert result.started is False and result.namespaces == []
    assert result.backend.snapshot["executions_reserved"] == 0
    assert result.report["records"] == [] and result.report["outcome"] == "inconclusive"
    assert result.report["terminal_decision"]["reason"] == reason
    assert result.receipt == {"identity": result.lab.identity, "status": "closed",
                              "connection_count": 0, "request_count": 0}
    assert inspect_assessment(result.evidence_path) == result.report
    assert_reaped(processes)


def test_owned_lab_first_start_follows_consumed_grant_and_durable_execution_event(
        tmp_path, monkeypatch, processes):
    # These scripted grants exercise enforcement, not actual human consent.
    grants, starts = [], []
    original = OwnedLab.start

    def start(lab, *args, **kwargs):
        events = [json.loads(line) for line in
                  (tmp_path / "audit" / "events.jsonl").read_text().splitlines()]
        assert events[-1]["event_type"] == "execution_started"
        action_id = events[-1]["action_id"]
        approvals = [row for row in events if row["event_type"] == "approval_consumed"
                     and row["action_id"] == action_id]
        assert len(approvals) == 1
        assert approvals[0]["approval_reference"] in grants
        starts.append(lab.started)
        return original(lab, *args, **kwargs)

    def approve(controller, raw, *, control):
        control.check()
        grant = controller.approvals.issue(parse_action(raw), controller.policy).reference
        grants.append(grant)
        return grant

    monkeypatch.setattr(OwnedLab, "start", start)
    result = run_workflow(tmp_path, approval=True, grant=approve)
    assert len(grants) == 3 and len(set(grants)) == 3
    assert starts and starts[0] is False
    assert result.report["outcome"] == "validated"
    assert all(grant not in json.dumps(result.report) for grant in grants)
    assert_reaped(processes)


def test_fresh_owned_lab_instance_resets_state_and_repeats_semantic_outcome(tmp_path, processes):
    first = run_workflow(tmp_path / "first")
    second = run_workflow(tmp_path / "second")
    assert first.lab.identity["instance_id"] != second.lab.identity["instance_id"]
    assert {key: value for key, value in first.lab.identity.items() if key != "instance_id"} == {
        key: value for key, value in second.lab.identity.items() if key != "instance_id"}
    assert first.report["outcome"] == second.report["outcome"] == "validated"
    assert first.report["terminal_decision"]["reason"] == second.report["terminal_decision"]["reason"]
    assert [row["observation"] for row in first.report["records"]] == [
        row["observation"] for row in second.report["records"]]
    for result in (first, second):
        assert [(row["owned_lab"]["connection_count"], row["owned_lab"]["request_count"])
                for row in result.artifacts] == [(1, 0), (2, 1), (3, 2)]
        assert inspect_assessment(result.evidence_path) == result.report
    assert_reaped(processes)


def test_cancellation_closes_started_owned_lab_without_a_second_action(tmp_path, processes):
    def cancel(configured, step):
        assert step["step"] == 1 and configured.lab.started
        configured.runner.cancel()

    result = run_workflow(tmp_path, on_step=cancel)
    assert result.summary["stop_reason"] == "session_cancelled"
    assert result.backend.snapshot["executions_reserved"] == 1
    assert result.receipt["connection_count"] == 1 and result.receipt["request_count"] == 0
    assert result.report["outcome"] == "inconclusive" and result.report["integrity_issues"] == []
    assert result.report["terminal_decision"]["reason"] == "session_cancelled"
    assert inspect_assessment(result.evidence_path) == result.report
    assert_reaped(processes)


def test_owner_death_refuses_later_action_and_destroys_lab_descendants(tmp_path, processes):
    configured = build()
    lab = configured.lab
    control = ExecutionControl(time.monotonic() + 30)
    with AuditSink(tmp_path / "audit" / "events.jsonl") as audit:
        controller = Controller(configured.policy, audit, configured.backend,
                                session_id=configured.session_id)
        try:
            first = controller.submit(discovery_action("a", 1), execute=True,
                                      execution_control=control, session_step=1)
            assert first["execution_status"] == "succeeded" and lab.started
            owner = lab._supervisor.processes["lab"]
            owned_processes = descendants(owner.pid)
            assert len(owned_processes) >= 2
            launches = len(processes)
            owner.kill()
            owner.wait(timeout=3)
            second = controller.submit(discovery_action("a", 2), execute=True,
                                       execution_control=control, session_step=2)
            assert second["execution_status"] == "blocked"
            assert second["reasons"] == ["isolation_unavailable"]
            assert len(processes) == launches
        finally:
            lab.close()
    assert_no_survivors(owned_processes)
    assert_reaped(processes)


def test_namespace_context_substitution_closes_pins_and_refuses_new_executor(tmp_path, processes):
    configured = build()
    lab = configured.lab
    control = ExecutionControl(time.monotonic() + 30)
    with AuditSink(tmp_path / "audit" / "events.jsonl") as audit:
        controller = Controller(configured.policy, audit, configured.backend,
                                session_id=configured.session_id)
        try:
            first = controller.submit(discovery_action("a", 1), execute=True,
                                      execution_control=control, session_step=1)
            assert first["execution_status"] == "succeeded"
            namespace_fds = lab._namespace_fds
            owner_tree = descendants(lab._supervisor.processes["lab"].pid)
            launches = len(processes)
            lab._lab_namespaces["net"] = os.readlink("/proc/self/ns/net")
            second = controller.submit(discovery_action("a", 2), execute=True,
                                       execution_control=control, session_step=2)
            assert second["execution_status"] == "blocked"
            assert second["reasons"] == ["isolation_unavailable"]
            assert len(processes) == launches
            for fd in namespace_fds:
                with pytest.raises(OSError) as caught:
                    os.fstat(fd)
                assert caught.value.errno == errno.EBADF
            with pytest.raises(IsolationUnavailable):
                lab.start(control)
        finally:
            lab.close()
    assert_no_survivors(owner_tree)
    assert_reaped(processes)


def test_active_cancellation_reaps_lab_and_leaves_only_inconclusive_partial_evidence(
        tmp_path, monkeypatch, processes):
    configured = build(case="d")
    lab = configured.lab
    evidence_path = tmp_path / "evidence"
    timers = []
    executors = []
    original = subprocess.Popen
    with AuditSink(tmp_path / "audit" / "events.jsonl") as audit, EvidenceStore(
            evidence_path, session_id=configured.session_id, policy=configured.policy, case="d",
            discovery=True, workflow=True, owned_lab=lab.identity) as evidence:
        provider = WorkflowAssessmentProvider("d", audit, evidence)
        runner = AuthoritySession(
            configured.policy, audit, configured.backend, configured.coordinator,
            configured.limits, session_id=configured.session_id, provider=provider, evidence=evidence)

        def launch(argv, *args, **kwargs):
            child = original(argv, *args, **kwargs)
            if Path(argv[0]).name == "nsenter":
                executors.append(child)
                if len(executors) == 3:
                    assert lab.started
                    timer = threading.Timer(0.3, runner.cancel)
                    timer.daemon = True
                    timers.append(timer)
                    timer.start()
            return child

        monkeypatch.setattr(subprocess, "Popen", launch)
        try:
            # A stopped executor cannot supply authenticated final counters.
            # Preserve the started record as unknown instead of inventing them.
            with pytest.raises(EvidenceUnavailable):
                runner.run(execute=True)
        finally:
            lab.close()
            for timer in timers:
                timer.cancel()
                timer.join(timeout=1)
    assert len(executors) == 3 and timers
    assert configured.backend.snapshot["executions_reserved"] == 3
    assert not (evidence_path / "report.json").exists()
    report = inspect_assessment(evidence_path)
    assert report["outcome"] == "inconclusive"
    assert "execution_completion_unknown" in report["integrity_issues"]
    assert_reaped(processes)
