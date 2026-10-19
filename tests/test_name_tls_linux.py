"""The 54 finite owned native corpus trials; scripted PTYs are test authority.

No fixture accepts a caller target, grant, binding, clock, executable or case
outside the frozen corpus. Scripted reviews demonstrate real isolated grant
mechanics and must never be reported as personal approval.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import subprocess
import sys
import termios
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import approval_isolation
from recon_cockpit.secure_agent import name_tls as diagnostic
from recon_cockpit.secure_agent import name_tls_contract as contract
from recon_cockpit.secure_agent import name_tls_context as context
from recon_cockpit.secure_agent import name_tls_native_runtime as native
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.name_tls_backend import AuthorizedNameTLSBackend
from recon_cockpit.secure_agent.name_tls_evidence import NameTLSEvidenceStore, inspect_trial
from recon_cockpit.secure_agent.name_tls_lab import NameTLSLab
from recon_cockpit.secure_agent.session_limits import SessionLimits

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def owned_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned disconnected name/TLS")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(NameTLSLab, "start", lambda *_a, **_kw: pytest.fail("host owner fallback"))
    monkeypatch.setattr(AuthorizedNameTLSBackend, "run", lambda *_a, **_kw: pytest.fail("host service fallback"))


@pytest.fixture
def diagnostics(monkeypatch, tmp_path):
    original = LinuxFixtureLauncher._cleanup
    paths = []
    def cleanup(self):
        try:
            return original(self)
        finally:
            if self._supervisor is not None:
                path = tmp_path / ("launcher-diagnostics-" + str(len(paths)) + ".json")
                rows = {key: bytes(value).decode("utf-8", "replace")
                        for key, value in self._supervisor.buffers.items()}
                path.write_text(json.dumps(rows, sort_keys=True))
                paths.append(path)
    monkeypatch.setattr(LinuxFixtureLauncher, "_cleanup", cleanup)
    yield paths


@pytest.fixture
def terminal(monkeypatch):
    master, slave = pty.openpty()
    os.set_blocking(slave, False)
    attributes = termios.tcgetattr(master)
    attributes[3] &= ~termios.ECHO
    termios.tcsetattr(master, termios.TCSANOW, attributes)
    monkeypatch.setattr(approval_isolation, "_open_terminal", lambda: os.dup(slave))
    try:
        yield master
    finally:
        os.close(slave)
        os.close(master)


def _scripted_review(approvals, raw, policy, terminal, control):
    action = parse_action(raw)
    def respond():
        prompt = bytearray()
        deadline = min(control.deadline, time.monotonic() + 8)
        while b"(blank denies): " not in prompt:
            assert select.select([terminal], [], [], max(0, deadline - time.monotonic()))[0], prompt
            prompt.extend(os.read(terminal, 4096))
            assert len(prompt) <= 16384
        challenge = re.search(rb"Type '(approve [0-9a-f]{16} [0-9a-f]{32})'", prompt)
        assert challenge is not None
        assert action.digest.encode("ascii") in prompt and policy.digest.encode("ascii") in prompt
        # Complete literal binding parameters must appear in the real review.
        for field, value in action.parameters.to_dict().items():
            assert field.encode("ascii") in prompt and str(value).encode("ascii") in prompt
        os.write(terminal, challenge.group(1) + b"\n")
        return bytes(prompt)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(respond)
        reference = approvals.review(action, policy, control=control)
        prompt = pending.result(timeout=8)
    assert reference is not None
    return {"reference": reference, "prompt_base64": base64.b64encode(prompt).decode("ascii")}


class NativeSession:
    """Test-only factory; grants still come from the isolated real reviewer."""

    def __init__(self, directory, configuration, case, *, evidence=True, require_approval=True, cancelled=None):
        self.directory = Path(directory)
        self.selected = contract.selection(configuration, case)
        self.started = time.monotonic()
        runtime = native.inspect_runtime(configuration, case, ExecutionControl(self.started + 15))
        self.session_id = str(uuid4())
        self.limits = SessionLimits(**contract.limits(self.selected))
        self.policy = contract.policy_for_selection(self.selected, require_approval=require_approval)
        self.lab = NameTLSLab(self.selected, self.session_id, self.limits, execute=True, runtime=runtime)
        self.original = AuthorizedNameTLSBackend(self.policy, self.session_id, self.limits, self.lab, execute=True)
        self.control = ExecutionControl(min(self.started + 75, time.monotonic() + 60), cancelled=cancelled)
        self.manifest = {"schema_version": "1", "assessment_id": str(uuid4()), "session_id": self.session_id,
            "selection": self.selected, "slots": list(contract.operation_plan(self.selected)),
            "policy": self.policy.to_dict(), "limits": contract.limits(self.selected), "runtime": runtime,
            "identity": self.lab.identity, "execute": True, "unattended_owned_lab_test": not require_approval}
        self.use_evidence = evidence
        self.outcomes, self.reviews = [], []
        self.approval_messages = []
        self.closure = None

    def __enter__(self):
        self.stack = ExitStack()
        try:
            self.evidence = (self.stack.enter_context(NameTLSEvidenceStore(self.directory, self.manifest,
                deadline=self.control.deadline + 5)) if self.use_evidence else None)
            if not self.use_evidence:
                self.directory.mkdir(mode=0o700, parents=True)
            self.audit = self.stack.enter_context(LinuxAuditSink(self.directory / "audit.jsonl", launch_witness=True))
            self.approvals = self.stack.enter_context(LinuxApprovalService(self.policy, self.session_id, launch_witness=True))
            # Retain exact real worker messages. Wrappers observe the existing
            # protocol and cannot supply a grant, receipt or approval result.
            original_send, original_reply = self.approvals._send, self.approvals._reply
            pending_request = []
            def observed_send(raw, **kwargs):
                original_send(raw, **kwargs)
                assert pending_request == []
                pending_request.append(json.loads(raw))
            def observed_reply():
                reply = original_reply()
                assert len(pending_request) == 1
                self.approval_messages.append({"request": pending_request.pop(), "reply": deepcopy(reply)})
                return reply
            self.approvals._send, self.approvals._reply = observed_send, observed_reply
            self.backend = self.stack.enter_context(LinuxFixtureLauncher(self.original, audit=self.audit, approvals=self.approvals))
            self.controller = Controller(self.policy, self.audit, self.backend, self.approvals,
                session_id=self.session_id, evidence=self.evidence)
            return self
        except BaseException:
            self.stack.close()
            raise

    def action(self, slot):
        if slot.startswith("dns_"):
            return contract.dns_action(self.selected, self.lab.identity, slot)
        return contract.service_action(self.selected, self.lab.identity, slot,
                                       self.outcomes[-1]["untrusted_result"]["name_tls_ledger"]["binding"])

    def submit(self, slot, *, terminal=None):
        raw = self.action(slot)
        review = None if terminal is None else _scripted_review(self.approvals, raw, self.policy, terminal, self.control)
        outcome = self.controller.submit(raw, execute=True, interactive=terminal is not None,
            approval_reference=None if review is None else review["reference"], execution_control=self.control,
            session_step=len(self.outcomes) + 1)
        self.outcomes.append(outcome)
        self.reviews.append(review)
        return outcome

    def close_owner(self):
        self.closure = self.backend.close()
        assert self.closure["launcher_cleanup_verified"] is True
        process = getattr(self.backend, "_process", None)
        if process is not None:
            assert process.poll() is not None
        return self.closure

    def finalize(self, *, probes=None):
        assert self.evidence is not None
        self.close_owner()
        return self.evidence.finalize(self.outcomes, closure=self.closure,
            elapsed_ms=round((time.monotonic() - self.started) * 1000), probes=probes)

    def __exit__(self, *exc):
        try:
            self.close_owner()
        finally:
            self.stack.__exit__(*exc)


def _acknowledged_state(session):
    result = session.outcomes[-1]["untrusted_result"]
    process = session.backend._process
    approval_process = session.approvals._process
    assert process is not None and approval_process is not None
    return {"owner_state_source": "last_acknowledged_result",
            "ledger": deepcopy(result["name_tls_ledger"]), "messages": deepcopy(result["name_tls_messages"]),
            "backend_snapshot": dict(session.backend.snapshot), "backend_context": deepcopy(session.backend._lab_context),
            "launcher_pid": process.pid, "launcher_alive": process.poll() is None,
            "approval_worker_pid": approval_process.pid, "approval_worker_alive": approval_process.poll() is None}


def _owner_record(session, service_review):
    assert session.closure is not None
    worker = session.approvals._process
    return {"manifest": deepcopy(session.manifest), "dns_outcome": deepcopy(session.outcomes[0]),
            "closure": deepcopy(session.closure),
            "audit_events": [json.loads(line) for line in (session.directory / "audit.jsonl").read_bytes().splitlines()],
            "approval_messages": deepcopy(session.approval_messages),
            "approval_worker": {"broker_id": session.approvals._identity, "pid": worker.pid,
                                "checks": session.approvals.boundary_checks},
            "dns_review": deepcopy(session.reviews[0]), "service_review": deepcopy(service_review)}


def _inspect_n15(path):
    """Data-only composite replay; this function cannot create an owner/grant."""
    from recon_cockpit.secure_agent.name_tls_evidence import _decode, validate_probe_evidence
    raw = path.read_bytes()
    probes = _decode(raw)
    primary = probes["owners"][0]
    outcome = primary["dns_outcome"]
    before = hashlib.sha256(raw).hexdigest()
    passed = validate_probe_evidence(probes, manifest=primary["manifest"],
        results=[outcome["untrusted_result"]],
        outcomes=[{key: value for key, value in outcome.items() if key != "untrusted_result"}])
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    return {"schema_version": "1", "case_passed": passed is True,
            "classification": "expected_negative" if passed else "incomplete", "case": "N15",
            "configuration": primary["manifest"]["selection"]["configuration"],
            "test_authority": "scripted_owned_pty", "composite_sha256": before,
            "actual_provider_calls": 0, "owner_count": len(probes["owners"])}


def _n15_composite(tmp_path, configuration, terminal):
    """Closed grant replay plus an unexpired foreign donor, exactly 3 owners."""
    started = time.monotonic()
    owners, attempts = [], []
    with NativeSession(tmp_path / "closed-owner", configuration, "N15", evidence=False) as primary:
        dns = primary.submit("dns_1", terminal=terminal)
        assert dns["execution_status"] == "succeeded", dns
        action = primary.action("http")
        review = _scripted_review(primary.approvals, action, primary.policy, terminal, primary.control)
        before = _acknowledged_state(primary)
        primary.close_owner()
        assert primary.backend._process.poll() is not None
        outcome = primary.controller.submit(action, execute=True, interactive=True,
            approval_reference=review["reference"], execution_control=primary.control, session_step=2)
        assert outcome["execution_status"] == "blocked" and outcome["reasons"] == ["isolation_unavailable"]
        assert outcome["approval_reference"] == review["reference"] and "untrusted_result" not in outcome
        after = _acknowledged_state(primary)
        assert not after["launcher_alive"] and after["approval_worker_alive"]
        attempts.append({"kind": "closed_owner", "owner_index": 0, "proposal": action,
            "proposal_sha256": contract.digest(action), "outcome": outcome,
            "before": before, "after": after, "closure": primary.closure})
        owners.append(_owner_record(primary, review))

    opposite = "B" if configuration == "A" else "A"
    # Each owns its original independent 60-second control. Creating the
    # recipient cannot extend the donor's lifetime, TTL or grant expiration.
    with NativeSession(tmp_path / "live-donor", opposite, "N15", evidence=False) as donor:
        dns = donor.submit("dns_1", terminal=terminal)
        assert dns["execution_status"] == "succeeded", dns
        action = donor.action("http")
        review = _scripted_review(donor.approvals, action, donor.policy, terminal, donor.control)
        with NativeSession(tmp_path / "fresh-recipient", configuration, "N15", evidence=False) as recipient:
            dns = recipient.submit("dns_1", terminal=terminal)
            assert dns["execution_status"] == "succeeded", dns
            donor_before, recipient_before = _acknowledged_state(donor), _acknowledged_state(recipient)
            binding = donor_before["ledger"]["binding"]
            expires = donor.control.deadline - 60 + binding["expires_at_us"] / 1000000
            ttl_remaining = int((expires - time.monotonic()) * 1000000)
            owner_remaining = int(donor.control.remaining() * 1000000)
            assert ttl_remaining > 0 and owner_remaining > 0
            outcome = recipient.controller.submit(action, execute=True, interactive=True,
                approval_reference=review["reference"], execution_control=recipient.control, session_step=2)
            decision = recipient.policy.evaluate(parse_action(action))
            assert decision.decision == "deny" and outcome["reasons"] == list(decision.reasons)
            assert outcome["execution_status"] == "blocked" and outcome["approval_reference"] is None
            # A real consume after the rejected transplant proves this was a
            # valid, still-live donor grant, not a guessed or already-burned ID.
            assert donor.approvals.consume(review["reference"], parse_action(action), donor.policy) is None
            donor_after, recipient_after = _acknowledged_state(donor), _acknowledged_state(recipient)
            assert donor_after == donor_before and recipient_after == recipient_before
            assert donor_after["launcher_alive"] and recipient_after["launcher_alive"]
            donor.control.check()
            assert time.monotonic() < expires
            attempts.append({"kind": "cross_configuration_live_donor", "donor_index": 1, "recipient_index": 2,
                "proposal": action, "proposal_sha256": contract.digest(action), "outcome": outcome,
                "donor_monotonic_remaining_us": owner_remaining, "donor_binding_remaining_us": ttl_remaining,
                "donor_before": donor_before, "donor_after": donor_after,
                "recipient_before": recipient_before, "recipient_after": recipient_after})
            recipient.close_owner()
            donor.close_owner()
            owners.extend((_owner_record(donor, review), _owner_record(recipient, None)))

    assert len({row["manifest"]["identity"]["owner_id"] for row in owners}) == 3
    elapsed_ms = round((time.monotonic() - started) * 1000)
    assert elapsed_ms <= 200000
    primary = owners[0]["manifest"]
    probes = {"schema_version": "1", "selection_sha256": primary["selection"]["selection_sha256"],
        "owner_identity_sha256": primary["identity"]["owner_identity_sha256"], "case": "N15",
        "instrumented": True, "status": "attempted", "waited_us": 0, "test_authority": "scripted_owned_pty",
        "owners": owners, "attempts": attempts, "elapsed_ms": elapsed_ms}
    raw = json.dumps(probes, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    assert len(raw) <= 1048576
    path = tmp_path / "n15-composite.json"
    with path.open("xb") as stream:
        stream.write(raw)
    path.chmod(0o600)
    report = _inspect_n15(path)
    assert report["case_passed"] is True, report
    before = (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
    assert _inspect_n15(path) == report
    assert before == (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
    return report


def _immutable_replay(directory, report):
    before = {p.name: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mode, p.stat().st_mtime_ns)
              for p in directory.iterdir()}
    assert inspect_trial(directory) == report
    replay = subprocess.run([sys.executable, "scripts/name_tls_native.py", "inspect", str(directory)],
                            capture_output=True, timeout=45, check=False)
    assert replay.returncode == (0 if report["case_passed"] else 1), replay.stderr.decode("utf-8", "replace")
    assert json.loads(replay.stdout) == report
    assert before == {p.name: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mode, p.stat().st_mtime_ns)
                      for p in directory.iterdir()}
    assert report["actual_provider_calls"] == 0
    assert report["credentials_used"] is report["attached_targets"] is False
    assert report["closure"]["launcher_cleanup_verified"] is True


def _trial(tmp_path, diagnostics, configuration, case, *, order="default"):
    directory = tmp_path / "trial"
    try:
        report = diagnostic.run_trial(directory, configuration=configuration, case=case, order=order,
                                      execute=True, unattended_owned_lab_test=True)
        assert report["case_passed"] is True, report
        _immutable_replay(directory, report)
        return report
    except BaseException:
        for path in diagnostics:
            print(path.read_text())
        raise


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("case", contract.public.CASES)
def test_native_core_case(tmp_path, diagnostics, terminal, record_property, configuration, case):
    if case == "N15":
        report = _n15_composite(tmp_path, configuration, terminal)
    else:
        report = _trial(tmp_path, diagnostics, configuration, case)
    assert report["case_passed"] is True
    record_property("gate_id", f"case/{configuration}/{case}")
    record_property("case_passed", True)
    record_property("actual_provider_calls", 0)


@pytest.mark.parametrize("configuration", ("A", "B"))
def test_native_reverse_o4(tmp_path, diagnostics, record_property, configuration):
    report = _trial(tmp_path, diagnostics, configuration, "O4", order="tls_first")
    assert report["slots"] == ["dns_1", "tls", "http"]
    record_property("gate_id", f"order/{configuration}/O4_dns_tls_http")
    record_property("case_passed", True)


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("slot,case", (("dns_1", "O1"), ("http", "O2"), ("tls", "O3")))
def test_native_default_approval_refusal(tmp_path, terminal, record_property, configuration, slot, case):
    directory = tmp_path / "trial"
    with NativeSession(directory, configuration, case) as session:
        if slot != "dns_1":
            prerequisite = session.submit("dns_1", terminal=terminal)
            assert prerequisite["execution_status"] == "succeeded", prerequisite
            assert prerequisite["untrusted_result"]["name_tls_ledger"]["binding"] is not None
        before = dict(session.backend.snapshot)
        outcome = session.submit(slot)
        assert outcome["execution_status"] == "blocked"
        assert outcome["reasons"] == ["noninteractive_approval_required"]
        assert "untrusted_result" not in outcome
        assert dict(session.backend.snapshot) == before
        report = session.finalize()
    assert report["case_passed"] is True and report["classification"] == "approval_refused"
    _immutable_replay(directory, report)
    record_property("gate_id", f"default_refusal/{configuration}/{contract.operation(slot)}")
    record_property("case_passed", True)
