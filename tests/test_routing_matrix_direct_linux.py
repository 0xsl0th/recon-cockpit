"""Actual witnessed calls bypassing run_trial still stop before later startup.

The first selected fault runs real stock traffic and retains its successful
native exit. A test-only rejection marker identifies the production gate;
a second tripwire fails if a later lab/service start is reached. These are
instrumented enforcement trials, not completed legitimate assessments.
"""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import routing_backend, routing_contract as contract
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.routing_backend import AuthorizedRoutingBackend
from recon_cockpit.secure_agent.routing_evidence import _matrix_case_outcome
from recon_cockpit.secure_agent.routing_lab import RoutingLab
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_routing_lifecycle_linux import _save, _pin_owned_tree, _assert_pinned_tree_reaped
from test_routing_linux import owned_only
from test_secure_fixture_launcher_linux import instrument

pytestmark = pytest.mark.integration


def _observe_stop_before_second_start(source):
    refusal = '                raise IsolationUnavailable("Routing declared negative already attempted")'
    startup = '            self.lab.start(control)'
    assert source.count(refusal) == source.count(startup) == 1
    source = source.replace(refusal,
        '                __import__("os").write(2, b"EXPECTED-ROUTING-DECLARED-NEGATIVE-STOP")\n' + refusal)
    source = source.replace(startup,
        '            if self._sequence > 1:\n'
        '                __import__("os").write(2, b"UNEXPECTED-ROUTING-LATER-LAB-START")\n'
        '                raise ValueError("routing_test_later_start_reached")\n' + startup)
    compile(source, "routing-direct-negative-observer", "exec")
    return source


@pytest.mark.parametrize("deployment,profile,first,later", (
    ("apache-B", "http_headers_N1", "http_headers", "ssh_keys"),
    ("nginx-A", "ssh_nmap_N1", "ssh_nmap", "http_headers"),
))
def test_native_successful_negative_blocks_direct_witnessed_continuation(
        tmp_path, monkeypatch, record_property, owned_only, deployment, profile, first, later):
    monkeypatch.setattr(RoutingLab, "start", lambda *_a, **_kw: pytest.fail("host topology fallback"))
    monkeypatch.setattr(AuthorizedRoutingBackend, "run", lambda *_a, **_kw: pytest.fail("host execution fallback"))
    source_path = Path(routing_backend.__file__)
    original_source = source_path.read_bytes()
    instrument(tmp_path, monkeypatch, _observe_stop_before_second_start, "routing_backend")
    selected = contract.selection(deployment=deployment, case_profile=profile)
    session = str(uuid4())
    runtime = contract.inspect_runtime(selected, ExecutionControl(time.monotonic() + 60))
    limits = SessionLimits(**contract.limits(selected))
    policy = contract.policy_for_selection(selected, require_approval=False)
    metadata = RoutingLab(selected, session, limits, execute=True, runtime=runtime)
    backend = AuthorizedRoutingBackend(policy, session, limits, metadata, execute=True)
    control = ExecutionControl(time.monotonic() + 60)
    pins, launcher = {}, None
    state = {"test_kind": "instrumented_direct_witnessed_negative_stop", "selection": selected,
        "planned_actions": [first, later], "test_passed": False, "personal_approval_claimed": False,
        "actual_provider_calls": 0, "actual_cost_microusd": 0, "useful_actions_completed": 0,
        "source_sha256": hashlib.sha256(original_source).hexdigest(),
        "instrumented_source_sha256": hashlib.sha256((tmp_path / "routing_backend.py").read_bytes()).hexdigest()}
    try:
        with LinuxAuditSink(tmp_path / "audit.jsonl", launch_witness=True) as audit, \
                LinuxApprovalService(policy, session, launch_witness=True) as approvals:
            with LinuxFixtureLauncher(backend, audit=audit, approvals=approvals) as launcher:
                controller = Controller(policy, audit, launcher, approvals, session_id=session)
                first_outcome = controller.submit(contract.action(selected, first), execute=True,
                    execution_control=control, session_step=1)
                _save(tmp_path / "first-outcome.json", first_outcome)
                assert first_outcome["execution_status"] == "succeeded", first_outcome
                result = first_outcome["untrusted_result"]
                grading = _matrix_case_outcome(first, result, result["tool_observation"], selected)
                assert grading["expected_negative"] and grading["native_response_verified"]
                assert not grading["useful_completion"]
                ledger = deepcopy(result["routing_ledger"])
                assert ledger["terminal"] and ledger["terminal_reason"] == "declared_negative_completed"
                assert len(ledger["actions"]) == ledger["counters"]["actions"] == 1
                assert ledger["active_action_sequence"] is ledger["active_connection"] is None
                assert result["routing_service"]["closure"]["daemon_processes_reaped"]
                context, snapshot = deepcopy(launcher._lab_context), dict(launcher.snapshot)
                process = launcher._process
                pins, workers = _pin_owned_tree(process)
                state.update(first_execution_status=first_outcome["execution_status"], first_grading=grading,
                    last_acknowledged_ledger=ledger, last_acknowledged_snapshot=snapshot,
                    observed_processes=sorted(pins), observed_workers=workers)

                # Deliberately bypass the high-level trial loop. Real audit and
                # approval-witness channels still precede this second request.
                second = controller.submit(contract.action(selected, later), execute=True,
                    execution_control=control, session_step=2)
                _save(tmp_path / "second-outcome.json", second)
                assert second["execution_status"] == "blocked", second
                assert second.get("untrusted_result") == {"status": "blocked"}
                closure = launcher.close()
                diagnostic = bytes(launcher._supervisor.buffers["worker_err"])
                assert b"EXPECTED-ROUTING-DECLARED-NEGATIVE-STOP" in diagnostic, diagnostic
                assert b"UNEXPECTED-ROUTING-LATER-LAB-START" not in diagnostic, diagnostic
                assert launcher._closed and launcher._cleanup_verified and process.poll() is not None
                assert launcher._lab_context == context and dict(launcher.snapshot) == snapshot
                assert closure["launcher_cleanup_verified"] and closure["counters_source"] == "last_acknowledged_result"
                assert closure["connection_count"] == ledger["counters"]["connections"]
                assert closure["request_count"] == ledger["counters"]["http_requests"] + ledger["counters"]["kex_exchanges"]
                _assert_pinned_tree_reaped(pins)
                state.update(second_execution_status=second["execution_status"], closure=closure,
                    second_lab_or_service_started=False, second_client_launched=False,
                    expected_backend_refusal_observed=True, last_acknowledged_only=True,
                    process_identities_reaped=len(pins))
        events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
        assert sum(row["event_type"] == "execution_started" for row in events) == 2
        assert source_path.read_bytes() == original_source
        state["test_passed"] = True
        record_property("case_profile", profile)
        record_property("first_native_execution_status", "succeeded")
        record_property("expected_negative", True)
        record_property("second_client_launched", False)
        record_property("actual_provider_calls", 0)
    finally:
        if launcher is not None and launcher._supervisor is not None:
            state["launcher_diagnostics"] = {name: bytes(raw).decode("utf-8", "replace")
                for name, raw in launcher._supervisor.buffers.items()}
        _save(tmp_path / "direct-negative-stop.json", state)
        for descriptor in pins.values():
            os.close(descriptor)
