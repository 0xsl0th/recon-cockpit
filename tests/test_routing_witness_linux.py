"""Real isolated routing launch denials; scripted PTYs are not owner approval.

The accepted generic suites exercise the witness protocols comprehensively.
These cases cover the new routing tag, bootstrap and exact profile at their
real readers. No successful topology, tool or simulated provider is substituted.
"""

from contextlib import contextmanager
import json
import os
import sys
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import launcher_protocol, routing_contract as contract
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.routing_backend import AuthorizedRoutingBackend
from recon_cockpit.secure_agent.routing_lab import RoutingLab
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_secure_approval_linux import instrument_worker, scripted_review, terminal
from test_secure_audit_witness import intent
from test_secure_audit_witness_linux import instrument_writer
from test_secure_fixture_launcher_linux import instrument


pytestmark = pytest.mark.integration


def _owned_linux_only():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for disconnected routing witness checks")
    assert sys.platform == "linux" and os.geteuid() != 0


@pytest.fixture(autouse=True)
def owned_only(monkeypatch):
    _owned_linux_only()
    monkeypatch.setattr(RoutingLab, "start", lambda *_: pytest.fail("host topology fallback"))
    monkeypatch.setattr(AuthorizedRoutingBackend, "run", lambda *_a, **_kw: pytest.fail("host tool fallback"))


@pytest.fixture(scope="module")
def native_runtime():
    _owned_linux_only()
    # Inspect actual immutable clients and daemons, outside the timed proof
    # exchange. The production launcher independently checks these again.
    return contract.inspect_runtime(contract.selection(), ExecutionControl(time.monotonic() + 60))


def _observe_denial_before_admission(source):
    """Observe genuine reader refusals and fail if admission is ever reached."""
    for reader, marker in (("witness_reader", "AUDIT"), ("approval_reader", "APPROVAL")):
        original = f"                    {reader}.require(config, action, control)"
        assert source.count(original) == 1
        source = source.replace(original,
            "                    try:\n"
            f"                        {reader}.require(config, action, control)\n"
            "                    except ValueError as error:\n"
            f"                        os.write(2, b'EXPECTED-ROUTING-{marker}-REFUSAL:' + str(error).encode('ascii', 'replace'))\n"
            "                        raise")
    original = "                granted = gate.admit("
    assert source.count(original) == 1
    source = source.replace(original,
        "                os.write(2, b'UNEXPECTED-ROUTING-ADMISSION')\n"
        "                raise ValueError('routing_witness_test_admission_tripwire')\n" + original)
    compile(source, "routing-launcher-denial-observer", "exec")
    return source


@contextmanager
def boundary(tmp_path, native_runtime, *, require_approval):
    selected, session = contract.selection(), str(uuid4())
    policy = contract.policy_for_selection(selected, require_approval=require_approval)
    limits = SessionLimits(**contract.limits(selected))
    lab = RoutingLab(selected, session, limits, runtime=native_runtime)
    backend = AuthorizedRoutingBackend(policy, session, limits, lab, execute=True)
    with LinuxAuditSink(tmp_path / "audit.jsonl", launch_witness=True) as audit, \
            LinuxApprovalService(policy, session, launch_witness=True) as approvals:
        with LinuxFixtureLauncher(backend, audit=audit, approvals=approvals) as launcher:
            assert launcher._config["profile"] == contract.PROFILE
            assert launcher._witness_source is not None and launcher._approval_source is not None
            yield audit, approvals, launcher, policy, session
            assert lab.topology is None and lab.services is None and not lab.started


def _start_exact_routing_launcher(launcher, control):
    launcher._start(control)
    # An early namespace/bootstrap failure cannot satisfy these denial cases.
    assert launcher.boundary_checks == dict.fromkeys(launcher_protocol.CHECKS, True)
    assert launcher._process.poll() is None
    assert launcher._witness_reader is None and launcher._approval_reader is None
    assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}


def _assert_reader_refused(launcher, action, policy, control, marker):
    with pytest.raises(IsolationUnavailable):
        launcher.run(action, policy, control=control)
    assert launcher._closed and launcher._process.poll() is not None
    diagnostic = bytes(launcher._supervisor.buffers["worker_err"])
    assert b"EXPECTED-ROUTING-" + marker.encode("ascii") + b"-REFUSAL" in diagnostic, diagnostic
    assert b"UNEXPECTED-ROUTING-ADMISSION" not in diagnostic, diagnostic
    assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
    assert launcher._lab_context is None
    closed = launcher.close()
    assert closed["launcher_cleanup_verified"] is True
    assert closed["connection_count"] == closed["request_count"] == 0
    with pytest.raises(IsolationUnavailable):
        launcher.run(action, policy, control=ExecutionControl(time.monotonic() + 10))
    return diagnostic


@pytest.mark.parametrize("fault", ("missing", "fsync_failure"))
def test_routing_missing_or_nondurable_audit_never_reaches_admission(
        tmp_path, monkeypatch, native_runtime, fault):
    instrument(tmp_path, monkeypatch, _observe_denial_before_admission)
    if fault == "fsync_failure":
        def fail_fsync(source):
            assert source.count("os.fsync(fd)") == 1
            return source.replace("os.fsync(fd)", "raise OSError('OWNED-ROUTING-FSYNC-FAILURE')")
        instrument_writer(tmp_path, monkeypatch, fail_fsync)
    control = ExecutionControl(time.monotonic() + 40)
    action = parse_action(contract.action(contract.selection(), "http_headers"))
    with boundary(tmp_path, native_runtime, require_approval=False) as (audit, _, launcher, policy, session):
        _start_exact_routing_launcher(launcher, control)
        if fault == "fsync_failure":
            with pytest.raises(AuditUnavailable):
                audit.emit(intent(action, policy, session, backend=contract.BACKEND))
            assert audit._process.poll() is not None
        else:
            # A missing proof and closed genuine producer cannot become a host
            # assertion of durability. The launcher already owns its reader.
            audit.close()
            assert (tmp_path / "audit.jsonl").read_bytes() == b""
        _assert_reader_refused(launcher, action, policy, control, "AUDIT")


@pytest.mark.parametrize("fault", ("missing_consumed_proof", "replayed_consumed_proof"))
def test_routing_durable_intent_cannot_replace_missing_or_replayed_required_approval(
        tmp_path, monkeypatch, native_runtime, terminal, fault):
    instrument(tmp_path, monkeypatch, _observe_denial_before_admission)
    if fault == "replayed_consumed_proof":
        def duplicate_real_proof(source):
            original = "                    witness_sequence += 1"
            assert source.count(original) == 1
            # Replay the exact real worker-produced packet, after the real
            # one-use grant was consumed. No synthetic successful proof exists.
            return source.replace(original,
                "                    if os.write(witness_channel.fileno(), encoded) != len(encoded):\n"
                "                        raise ValueError('routing_test_replay_short_write')\n" + original)
        instrument_worker(tmp_path, monkeypatch, duplicate_real_proof)
    control = ExecutionControl(time.monotonic() + 40)
    action = parse_action(contract.action(contract.selection(), "ssh_keys"))
    with boundary(tmp_path, native_runtime, require_approval=True) as (audit, approvals, launcher, policy, session):
        reference = None
        if fault == "replayed_consumed_proof":
            reference, prompt = scripted_review(approvals, action, policy, terminal, control)
            assert reference is not None and action.digest.encode("ascii") in prompt
        _start_exact_routing_launcher(launcher, control)
        if reference is not None:
            # Emit proof after bootstrap, preserving its original freshness and
            # the action/session/policy bindings while testing actual replay.
            assert approvals.consume(reference, action, policy) is None
            assert approvals.consume(reference, action, policy) == "approval_unknown_or_replayed"
        event = intent(action, policy, session, backend=contract.BACKEND)
        event["approval_reference"] = reference or "a" * 48
        audit.emit(event)
        recorded = json.loads((tmp_path / "audit.jsonl").read_text())
        assert recorded["event_type"] == "execution_started" and recorded["backend"] == contract.BACKEND
        diagnostic = _assert_reader_refused(launcher, action, policy, control, "APPROVAL")
        if reference is not None:
            assert b"unexpected_approval_witness_output_or_exit" in diagnostic, diagnostic
            assert approvals._process.poll() is None
