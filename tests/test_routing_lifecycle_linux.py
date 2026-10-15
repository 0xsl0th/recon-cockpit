"""Opt-in owned cancellation/death witnesses; partial work is never completion.

The unattended policy is explicit test authority, not personal approval. Only
the tracked launcher tree is observed or terminated, and all endpoints remain
the fixed disconnected routing fixtures.
"""

from copy import deepcopy
import json
import os
from pathlib import Path
import select
import signal
import sys
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import routing_contract as contract
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.routing_backend import AuthorizedRoutingBackend
from recon_cockpit.secure_agent.routing_lab import RoutingLab
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_secure_fixture_launcher_linux import descendants
from test_secure_owned_launcher_linux import assert_reaped

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def owned_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned disconnected routing lifecycle")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(RoutingLab, "start", lambda *args: pytest.fail("host topology fallback"))
    monkeypatch.setattr(AuthorizedRoutingBackend, "run", lambda *args, **kwargs: pytest.fail("host execution fallback"))


def _save(path, value):
    with path.open("w", encoding="ascii") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, sort_keys=True, ensure_ascii=True, allow_nan=False)
        stream.write("\n")


def _pin_owned_tree(process):
    """Pin only descendants of the known Popen object, avoiding PID reuse."""
    observed = {process.pid, *descendants(process.pid)}
    pins, commands = {}, {}
    try:
        for pid in sorted(observed):
            try:
                descriptor = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            pins[pid] = descriptor
            try:
                commands[pid] = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            except FileNotFoundError:
                commands[pid] = []
        assert process.pid in pins
        workers = {}
        for name in ("routing_topology_worker", "routing_frontend_worker"):
            script = ("/app/recon_cockpit/secure_agent/" + name + ".py").encode("ascii")
            found = [pid for pid, argv in commands.items()
                     if argv and argv[0] == b"/usr/bin/python3" and script in argv]
            assert len(found) == 1, (name, commands)
            workers[name] = found[0]
        assert workers["routing_topology_worker"] != workers["routing_frontend_worker"]
        # The first action's native client and daemon have already been reaped.
        assert not any(argv and argv[0].startswith(b"/tool/") for argv in commands.values())
        return pins, workers
    except BaseException:
        for descriptor in pins.values():
            os.close(descriptor)
        raise


def _assert_pinned_tree_reaped(pins):
    poller = select.poll()
    pending = set(pins.values())
    for descriptor in pending:
        poller.register(descriptor, select.POLLIN)
    deadline = time.monotonic() + 3
    while pending and time.monotonic() < deadline:
        for descriptor, flags in poller.poll(50):
            if flags & select.POLLIN:
                pending.discard(descriptor)
                poller.unregister(descriptor)
    assert not pending, "an owned routing process survived lifecycle cleanup"
    assert_reaped(set(pins))


@pytest.mark.parametrize("stop", ("cancel", "launcher_death"))
def test_native_stop_after_useful_work_cannot_launch_second_action_or_reset_budget(
        tmp_path, monkeypatch, record_property, stop):
    selected = contract.selection()
    session_id = str(uuid4())
    cancelled = threading.Event()
    preflight = ExecutionControl(time.monotonic() + 60, cancelled)
    runtime = contract.inspect_runtime(selected, preflight)
    limits = SessionLimits(**contract.limits(selected))
    policy = contract.policy_for_selection(selected, require_approval=False)
    metadata = RoutingLab(selected, session_id, limits, execute=True, runtime=runtime)
    original = AuthorizedRoutingBackend(policy, session_id, limits, metadata, execute=True)
    control = ExecutionControl(time.monotonic() + 60, cancelled)
    audit_path = tmp_path / "audit.jsonl"
    pins, sends, starts = {}, [], []
    state = {"test_kind": "owned_routing_lifecycle", "stop": stop, "test_passed": False,
        "planned_actions": ["http_headers", "ssh_keys"], "second_action_launched": None,
        "completed_workflow": False, "personal_approval_claimed": False,
        "actual_provider_calls": 0, "actual_cost_microusd": 0}
    launcher = None
    try:
        with LinuxAuditSink(audit_path, launch_witness=True) as audit, \
                LinuxApprovalService(policy, session_id, launch_witness=True) as approvals:
            with LinuxFixtureLauncher(original, audit=audit, approvals=approvals) as launcher:
                # Observe the production transport; do not change or inject any
                # message. A queued intent is not evidence of native execution.
                real_send, real_start = launcher._send, launcher._start
                def observe_send(raw, **kwargs):
                    value = json.loads(raw)
                    if value.get("operation") == "execute":
                        sends.append(deepcopy(value))
                    return real_send(raw, **kwargs)
                def observe_start(actual_control):
                    starts.append(actual_control)
                    return real_start(actual_control)
                monkeypatch.setattr(launcher, "_send", observe_send)
                monkeypatch.setattr(launcher, "_start", observe_start)
                controller = Controller(policy, audit, launcher, approvals, session_id=session_id)
                first = controller.submit(contract.action(selected, "http_headers"), execute=True,
                    execution_control=control, session_step=1)
                state["first_execution_status"] = first["execution_status"]
                _save(tmp_path / "first-outcome.json", first)
                assert first["execution_status"] == "succeeded", first
                result = first["untrusted_result"]
                assert result["tool_observation"] is not None
                assert result["routing_service"]["selector"] == "http_headers"
                assert result["routing_service"]["closure"]["daemon_processes_reaped"] is True
                ledger = deepcopy(result["routing_ledger"])
                assert ledger["counters"]["actions"] == ledger["counters"]["connections"] == 1
                assert ledger["counters"]["http_requests"] == 1 and ledger["counters"]["kex_exchanges"] == 0
                assert ledger["active_connection"] is None and ledger["active_action_sequence"] is None
                before = dict(launcher.snapshot)
                assert before == {"executions_reserved": 1, "output_bytes_reserved": 2048}
                context = deepcopy(launcher._lab_context)
                process = launcher._process
                assert process is launcher._supervisor.processes["worker"] and process.poll() is None
                pins, workers = _pin_owned_tree(process)
                state.update(topology_sha256=contract.digest(result["routing_topology"]),
                    last_acknowledged_ledger=ledger, reservations_before_stop=before,
                    observed_processes=sorted(pins), observed_workers=workers)

                if stop == "cancel":
                    cancelled.set()
                    with pytest.raises(ExecutionStopped, match="session_cancelled"):
                        controller.submit(contract.action(selected, "ssh_keys"), execute=True,
                            execution_control=control, session_step=2)
                    state["second_outcome"] = {"execution_status": "cancelled_before_submission",
                                                "reason": "session_cancelled"}
                else:
                    # Target the exact tracked launcher process, not an inferred
                    # PID, unrelated daemon or broad process group.
                    signal.pidfd_send_signal(pins[process.pid], signal.SIGKILL)
                    process.wait(timeout=3)
                    try:
                        second = controller.submit(contract.action(selected, "ssh_keys"), execute=True,
                            execution_control=control, session_step=2)
                    except AuditUnavailable as exc:
                        # The dead launcher owned the audit-witness reader.
                        # Persisting an intent can succeed while delivering its
                        # witness fails; submit must then escape before run().
                        # Record the exception, not a fabricated tool outcome.
                        assert str(exc) == "audit_unavailable"
                        assert audit._failed and audit._closed
                        state["second_submission_failure"] = {
                            "exception_type": type(exc).__name__, "reason": str(exc)}
                    else:
                        state["second_outcome"] = second
                        assert second["execution_status"] == "blocked", second
                        assert second.get("untrusted_result") in (None, {"status": "blocked"})

                closure = launcher.close()
                state["closure"] = closure
                assert closure["launcher_cleanup_verified"] is True
                assert closure["counters_source"] == "last_acknowledged_result"
                assert closure["connection_count"] == ledger["counters"]["connections"]
                assert closure["request_count"] == ledger["counters"]["http_requests"] + ledger["counters"]["kex_exchanges"]
                assert launcher._closed and launcher._cleanup_verified and process.poll() is not None
                assert launcher._process is process and dict(launcher.snapshot) == before
                assert launcher._lab_context == context
                assert len(starts) == len(sends) == 1
                assert sends[0]["action"] == contract.action(selected, "http_headers")
                _assert_pinned_tree_reaped(pins)
                # A replacement control cannot reopen the closed owner or reset
                # the retained counters after cancellation/death.
                try:
                    retry = controller.submit(contract.action(selected, "ssh_keys"), execute=True,
                        execution_control=ExecutionControl(time.monotonic() + 5), session_step=2)
                except AuditUnavailable as exc:
                    assert stop == "launcher_death"
                    expected = "audit_closed" if "second_submission_failure" in state else "audit_unavailable"
                    assert str(exc) == expected and audit._failed and audit._closed
                    state["retry_submission_failure"] = {
                        "exception_type": type(exc).__name__, "reason": str(exc)}
                else:
                    state["retry_outcome"] = retry
                    assert retry["execution_status"] == "blocked"
                assert len(starts) == len(sends) == 1 and dict(launcher.snapshot) == before
                assert launcher._process is process and launcher.close() == closure
                state.update(reservations_after_stop=dict(launcher.snapshot),
                    acknowledged_actions=1, useful_actions_completed=1,
                    second_action_launched=False,
                    topology_owners_observed=1, execute_messages_sent=len(sends),
                    process_identities_reaped=len(pins))

        events = [json.loads(line) for line in audit_path.read_text().splitlines()]
        finished = [row for row in events if row["event_type"] == "execution_finished"]
        assert sum(row["execution_status"] == "succeeded" for row in finished) == 1
        second_id = contract.action(selected, "ssh_keys")["action_id"]
        assert not any(row["action_id"] == second_id and row["execution_status"] == "succeeded" for row in finished)
        state["test_passed"] = True
        record_property("lifecycle_stop", stop)
        record_property("useful_actions_completed", 1)
        record_property("second_action_launched", False)
        record_property("owned_processes_reaped", len(pins))
        record_property("actual_provider_calls", 0)
    finally:
        if launcher is not None and launcher._supervisor is not None:
            state["launcher_diagnostics"] = {name: bytes(raw).decode("utf-8", "replace")
                for name, raw in launcher._supervisor.buffers.items()}
        _save(tmp_path / "lifecycle-observation.json", state)
        for descriptor in pins.values():
            os.close(descriptor)
