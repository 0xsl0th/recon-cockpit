"""Owned TLS production trials and synthetic authority-gate exercises.

Unattended policies and scripted PTY responses are test data; these tests never
claim personal operator approval, credentials or authorization for other targets.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.approval_isolation import LinuxApprovalService
from recon_cockpit.secure_agent.assessment_inspection import inspect_saved_assessment
from recon_cockpit.secure_agent.audit_isolation import LinuxAuditSink
from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.coordinator_isolation import LinuxOfflineCoordinator
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
from recon_cockpit.secure_agent.network_tools_contract import action, BACKEND, BOUNDARY_FIELDS as BASE_BOUNDARY_FIELDS
from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab
from recon_cockpit.secure_agent.network_tools_runtime import inspect_tool_runtime
from recon_cockpit.secure_agent.network_tools_tls_posture_spec import (
    CASES, TOOL_VERSIONS, LIMITS, BOUNDARY_FIELDS, MAX_OWNER_BYTES, OWNER_REPRESENTATION, case_parts,
)
from recon_cockpit.secure_agent.session_limits import SessionLimits
from test_secure_approval_linux import scripted_review, terminal
from test_secure_audit_witness import intent
from test_secure_fixture_launcher_linux import descendants, instrument
from test_secure_nmap_cli import GATES
from test_secure_owned_launcher_linux import assert_reaped
from test_secure_network_tools_robustness_linux import _FixedProposal


pytestmark = pytest.mark.integration
POLICY = Path("examples/secure-agent-tls-posture-policy.json")
SUCCESS_CASES = tuple("tls-posture-" + version + "-legacy" for version in TOOL_VERSIONS.values())


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned TLS production trials")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, "run", lambda *a, **k: pytest.fail("host tool executed"))
    policy = json.loads(POLICY.read_text())
    assert set(policy["allowed_tools"]) == set(TOOL_VERSIONS)
    assert policy["require_approval"] is True


@contextmanager
def boundary(tmp_path, control, *, case, approval_required=True):
    definition = json.loads(POLICY.read_text())
    definition.update(require_approval=approval_required,
                      policy_version="synthetic-tls-posture-authority-gate-v1")
    policy, session = parse_policy(definition), str(uuid4())
    limits = SessionLimits(**LIMITS)
    lab = NetworkToolsLab(case, session, limits)
    backend = AuthorizedNetworkToolsBackend(policy, session, limits, lab, execute=True)
    backend._network_tools_manifest = inspect_tool_runtime(action(case)["tool_id"], control)
    with LinuxAuditSink(tmp_path / "audit.jsonl", launch_witness=True) as audit, \
            LinuxApprovalService(policy, session, launch_witness=True) as approvals:
        with LinuxFixtureLauncher(backend, audit=audit, approvals=approvals) as launcher:
            yield audit, approvals, launcher, policy, session


@pytest.mark.parametrize("case", CASES)
def test_real_production_tls_observation_owner_artifact_and_both_inspectors(
        tmp_path, capsys, record_property, case):
    version, variant = case_parts(case)
    safety = variant == "hrr"
    rejection = variant == "reject" or variant == "modern" and version in {"tls1", "tls1_1"}
    outcome = ("extra_client_hello_prevented" if safety else
               "explicit_protocol_rejection" if rejection else "handshake_completed")
    native_success = outcome == "handshake_completed"
    policy = json.loads(POLICY.read_text())
    policy.update(policy_version="synthetic-tls-posture-unattended-test-v1", require_approval=False)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy))
    evidence, audit = tmp_path / "evidence", tmp_path / "audit.jsonl"
    started = time.monotonic()
    code = cli.main(["--network-tool-assessment", case, "--assessment-dir", str(evidence),
        "--audit", str(audit), "--policy", str(policy_path), *GATES, "--execute"])
    output = capsys.readouterr()
    summary = json.loads(output.out)
    assert code in (0, 2), (summary, output.err)
    assert summary["assessment_outcome"] == "tls_posture_" + outcome, (summary, output.err)
    assert summary["actions_succeeded"] == int(native_success)
    assert summary["steps_attempted"] == 1 and summary["output_reserved_bytes"] == 8192
    assert summary["actual_provider_calls"] == 0 and summary["live_calls_enabled"] is False
    elapsed = time.monotonic() - started
    assert elapsed < 35
    record_property("trial_kind", "safety" if safety else "explicit_absence" if variant == "reject" else "ordinary")
    record_property("end_to_end_elapsed_ms", round(elapsed * 1000))
    record_property("useful_completion", int(not safety))
    record_property("unnecessary_refusals", 0 if not safety else "not_applicable")
    record_property("tested_retry_prevented", int(safety))
    record_property("actual_provider_calls", 0)
    record_property("actual_cost_microusd", 0)
    report = json.loads((evidence / "report.json").read_text())
    assert report["integrity_issues"] == []
    assert report["metrics"]["useful_actions_completed"] == int(not safety)
    assert report["metrics"]["tested_unauthorized_actions_blocked"] == int(safety)
    assert report["metrics"]["actual_cost_microusd"] == report["metrics"]["actual_provider_calls"] == 0
    closure = report["owned_lab"]["closure"]
    assert closure["status"] == "closed" and closure["connection_count"] == closure["request_count"] == 1
    assert len(report["records"]) == 1
    row = report["records"][0]
    assert row["action"]["tool_id"] == action(case)["tool_id"]
    assert row["action"]["target"] == "127.0.0.1" and row["action"]["parameters"]["port"] == 8080
    result_raw = (evidence / row["artifact"]["filename"]).read_bytes()
    assert len(result_raw) == row["artifact"]["bytes"] <= 65536
    result = json.loads(result_raw)
    assert set(result["boundary_checks"]) == BASE_BOUNDARY_FIELDS | BOUNDARY_FIELDS
    assert all(value is True for value in result["boundary_checks"].values())
    assert result["status"] == ("succeeded" if native_success else "failed")
    assert result["provenance"]["exit_code"] == (0 if native_success else 1)
    assert result["provenance"]["stop_reason"] is None and result["truncated"] is False
    stdout = base64.b64decode(result["raw_output_base64"], validate=True)
    stderr = base64.b64decode(result["raw_stderr_base64"], validate=True)
    assert result["bytes_received"] == len(stdout) + len(stderr) <= 8192
    owner_artifact = result["tls_posture_owner"]
    assert owner_artifact["filename"] == "tls-owner-" + row["execution_id"] + ".json"
    assert owner_artifact["representation"] == OWNER_REPRESENTATION
    owner_path = evidence / owner_artifact["filename"]
    owner_raw = owner_path.read_bytes()
    assert owner_path.stat().st_mode & 0o777 == 0o600
    assert len(owner_raw) == owner_artifact["bytes"] <= MAX_OWNER_BYTES
    assert hashlib.sha256(owner_raw).hexdigest() == owner_artifact["sha256"]
    assert result["owned_lab"]["tls_posture_owner_sha256"] == owner_artifact["sha256"]
    owner = json.loads(owner_raw)
    assert owner["mediation"]["completed"] and owner["mediation"]["threads_joined"]
    assert owner["diagnostic"]["completed"] and owner["diagnostic"]["client_hellos"] == 1
    assert owner["mediation"]["forwarded_client_hellos"] == 1
    if safety:
        assert owner["mediation"]["blocked"] is True
        assert owner["mediation"]["client_ingress_bytes"] > owner["mediation"]["client_forwarded_bytes"]
    else:
        assert owner["mediation"]["blocked"] is False
        assert owner["mediation"]["client_ingress_bytes"] == owner["mediation"]["client_forwarded_bytes"]
    details = row["observation"]["details"]
    assert details["outcome"] == outcome
    assert details["useful_task_completed"] is (not safety)
    assert details["extra_client_hello_prevented"] is safety
    assert details["owner_sha256"] == owner_artifact["sha256"]
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    assert cli.main(["--inspect-assessment", str(evidence)]) == 0
    assert json.loads(capsys.readouterr().out) == report
    assert inspect_saved_assessment(evidence) == report
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode) for p in evidence.iterdir()}
    events = [json.loads(line) for line in audit.read_text().splitlines()]
    assert sum(event["event_type"] == "execution_started" for event in events) == 1
    assert sum(event["event_type"] == "execution_finished" for event in events) == 1


@pytest.mark.parametrize("case", SUCCESS_CASES)
def test_synthetic_fresh_approval_is_consumed_once_for_each_version(tmp_path, terminal, case):
    control = ExecutionControl(time.monotonic() + 25)
    selected = parse_action(action(case))
    with boundary(tmp_path, control, case=case) as (audit, approvals, launcher, policy, session):
        reference, prompt = scripted_review(approvals, selected, policy, terminal, control)
        assert reference is not None and selected.digest.encode() in prompt
        controller = Controller(policy, audit, launcher, approvals, session_id=session)
        result = controller.submit(selected.to_dict(), execute=True, interactive=True,
            approval_reference=reference, execution_control=control)
        assert result["execution_status"] == "succeeded", result
        assert result["untrusted_result"]["tool_observation"]["useful_task_completed"] is True
        replay = controller.submit(selected.to_dict(), execute=True, interactive=True,
            approval_reference=reference, execution_control=control)
        assert replay["execution_status"] == "blocked" and replay["reasons"] == ["approval_unknown_or_replayed"]
        assert dict(launcher.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 8192}
        assert launcher.close()["request_count"] == 1
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert sum(event["event_type"] == "approval_consumed" for event in events) == 1


@pytest.mark.parametrize("case", SUCCESS_CASES)
def test_missing_consumed_approval_proof_blocks_before_admission(tmp_path, monkeypatch, case):
    instrument(tmp_path, monkeypatch, lambda source: source.replace("granted = gate.admit(",
        "os.write(2, b'UNEXPECTED-TLS-ADMISSION')\n                granted = gate.admit("))
    control = ExecutionControl(time.monotonic() + 20)
    selected = parse_action(action(case))
    with boundary(tmp_path, control, case=case) as (audit, approvals, launcher, policy, session):
        event = intent(selected, policy, session, backend=BACKEND)
        event["approval_reference"] = "a" * 48
        audit.emit(event)
        with pytest.raises((IsolationUnavailable, ExecutionStopped)):
            launcher.run(selected, policy, control=control)
        assert launcher._closed and launcher._process.poll() is not None
        assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
        assert b"UNEXPECTED-TLS-ADMISSION" not in bytes(launcher._supervisor.buffers["worker_err"])
        assert launcher.close()["request_count"] == 0


@pytest.mark.parametrize("case", SUCCESS_CASES)
def test_changed_action_burns_synthetic_grant_before_tool_launch(tmp_path, terminal, case):
    control = ExecutionControl(time.monotonic() + 20)
    selected = parse_action(action(case))
    with boundary(tmp_path, control, case=case) as (audit, approvals, launcher, policy, session):
        reference, _ = scripted_review(approvals, selected, policy, terminal, control)
        changed = {**selected.to_dict(), "rationale": "changed after exact review"}
        controller = Controller(policy, audit, launcher, approvals, session_id=session)
        result = controller.submit(changed, execute=True, interactive=True,
            approval_reference=reference, execution_control=control)
        assert result["execution_status"] == "blocked" and result["reasons"] == ["approval_action_changed"]
        retry = controller.submit(selected.to_dict(), execute=True, interactive=True,
            approval_reference=reference, execution_control=control)
        assert retry["execution_status"] == "blocked" and retry["reasons"] == ["approval_unknown_or_replayed"]
        assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
        assert launcher.close()["request_count"] == 0


@pytest.mark.parametrize("case", SUCCESS_CASES)
def test_synthetic_operator_denial_never_grants_tool_authority(tmp_path, terminal, case):
    control = ExecutionControl(time.monotonic() + 20)
    selected = parse_action(action(case))
    with boundary(tmp_path, control, case=case) as (audit, approvals, launcher, policy, session):
        reference, _ = scripted_review(approvals, selected, policy, terminal, control, answer=b"")
        assert reference is None
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            selected.to_dict(), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "blocked"
        assert dict(launcher.snapshot) == {"executions_reserved": 0, "output_bytes_reserved": 0}
        assert launcher.close()["request_count"] == 0


@pytest.mark.parametrize("case", SUCCESS_CASES)
def test_cancellation_after_native_openssl_exec_reaps_owner_and_client(tmp_path, monkeypatch, case):
    # Add a bounded fixture delay solely to hold a genuine native client open.
    def delay(source):
        anchor = '    ledger["client_hellos"] = 1\n    on_request()\n'
        assert source.count(anchor) == 1
        return source.replace(anchor, anchor + '    time.sleep(min(3, remaining(deadline)))\n')
    instrument(tmp_path, monkeypatch, delay, name="tls_posture_diagnostic_fixture")
    setup = ExecutionControl(time.monotonic() + 25)
    observed = set()
    with boundary(tmp_path, setup, case=case, approval_required=False) as (audit, approvals, launcher, policy, session):
        runner = AuthoritySession(policy, audit, launcher, LinuxOfflineCoordinator(), SessionLimits(**LIMITS),
            session_id=session, provider=_FixedProposal(case), approvals=approvals, deadline=setup.deadline)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(runner.run, execute=True, interactive=False)
            seen = False
            try:
                expiry = min(setup.deadline, time.monotonic() + 20)
                while time.monotonic() < expiry and not pending.done():
                    process = getattr(launcher, "_process", None)
                    if process is not None:
                        observed.add(process.pid)
                        observed.update(descendants(process.pid))
                    for pid in tuple(observed):
                        try:
                            command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0", 1)[0]
                        except (FileNotFoundError, ProcessLookupError):
                            continue
                        seen |= command == b"/tool/openssl"
                    if seen:
                        break
                    time.sleep(0.01)
                assert seen and not pending.done(), "actual confined OpenSSL did not reach its fixture wait"
                runner.cancel()
                summary = pending.result(timeout=8)
            finally:
                runner.cancel()
            assert summary["stop_reason"] == "session_cancelled"
            assert summary["session_status"] == "stopped" and summary["actions_succeeded"] == 0
            assert summary["steps_attempted"] == 1 and summary["output_reserved_bytes"] == 8192
            assert launcher._closed and launcher._process.poll() is not None
            assert launcher.close()["status"] == "closed"
            with pytest.raises(RuntimeError, match="session_already_used"):
                runner.run(execute=True)
        assert_reaped(observed)
