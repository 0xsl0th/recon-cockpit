"""The 59 separately pinned owner gates; six retain native/grant prerequisites."""

from copy import deepcopy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import name_tls as diagnostic
from recon_cockpit.secure_agent import name_tls_contract as contract, name_tls_ledger as ledger
from recon_cockpit.secure_agent import name_tls_evidence as evidence, name_tls_native_runtime as native
from recon_cockpit.secure_agent import name_tls_python_runtime as sources
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import _namespaces
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.models import parse_action
from test_name_tls_linux import NativeSession, _n15_composite, _scripted_review, _acknowledged_state, terminal

pytestmark = pytest.mark.integration
GATES = json.loads((Path(__file__).parents[1] / "docs/stage3-name-tls-native-gates.json").read_text())["owner"]
SPECIAL = {f"owner/A/B{number}" for number in (15, 16, 18, 19, 20, 21)}
INSTRUMENTED = [row for row in GATES if row["id"] not in SPECIAL]
assert len(GATES) == 59 and len(INSTRUMENTED) == 53 and len(SPECIAL) == 6


@pytest.fixture(autouse=True)
def owned_only():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for actual name/TLS owner gates")
    assert sys.platform == "linux" and os.geteuid() != 0


@pytest.fixture(scope="module")
def owner_runtime():
    cached = {}
    def get(gate):
        case = {"negative_dns_terminal": "N2", "negative_http_terminal": "N9",
                "negative_tls_terminal": "N11", "negative_profile_dns_prerequisite_active": "N11"}.get(gate["name"], "O4")
        order = "tls_first" if case == "O4" and gate["operation"] == "tls" else "default"
        if (case, order) not in cached:
            selected = contract.selection("A", case, order)
            control = ExecutionControl(time.monotonic() + 20)
            bundle = native.inspect_runtime("A", case, control)
            launcher = LinuxFixtureLauncher.__new__(LinuxFixtureLauncher)
            launcher._config = {"profile": contract.PROFILE, "case": selected}
            launcher._name_tls_runtime = bundle
            launcher._witness_source = launcher._approval_source = None
            closure, files = launcher._runtime(control)
            cached[(case, order)] = launcher, selected, bundle, closure, files
        return cached[(case, order)]
    return get


def save(path, raw):
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)


def _private_owner_trial(tmp_path, owner_runtime, gate, variant=None):
    launcher, selected, bundle, closure, files = owner_runtime(gate)
    identity = contract.identity(selected, str(uuid4()), bundle)
    helper = Path(__file__).with_name("name_tls_owner_probe.py")
    helper_bytes = helper.read_bytes()
    control = ExecutionControl(time.monotonic() + 10)
    descriptors = sources.snapshot_sources(bundle, tuple(sources.DESTINATIONS), control)
    helper_fd = os.memfd_create("name-tls-owner-probe", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        assert os.write(helper_fd, helper_bytes) == len(helper_bytes)
        os.lseek(helper_fd, 0, os.SEEK_SET)
        fcntl.fcntl(helper_fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK)
        command = launcher._command(closure, files, "instrumented-name-tls-owner", source_descriptors=descriptors)
        mount_at = command.index("--remount-ro")
        command[mount_at:mount_at] = ["--ro-bind-data", str(helper_fd), "/name_tls_owner_probe.py"]
        entry = command.index("/app/recon_cockpit/secure_agent/launcher_worker.py", command.index("--remount-ro"))
        command[entry:] = ["/name_tls_owner_probe.py", gate["id"]]
        initial = {"selection": selected, "identity": identity, "runtime": closure,
                   "host_namespaces": _namespaces(), "gate": gate, "probe_variant": variant}
        raw = json.dumps(initial, sort_keys=True, allow_nan=False).encode("ascii")
        assert len(raw) <= 262144
        save(tmp_path / "probe-input.json", raw)
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, pass_fds=(*descriptors.values(), helper_fd))
    finally:
        for descriptor in (*descriptors.values(), helper_fd):
            os.close(descriptor)
    try:
        stdout, stderr = process.communicate(raw, timeout=80)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=3)
        save(tmp_path / "probe-stdout.json", stdout)
        save(tmp_path / "probe-stderr.txt", stderr)
        pytest.fail("private owner probe exceeded independent watchdog")
    save(tmp_path / "probe-stdout.json", stdout)
    save(tmp_path / "probe-stderr.txt", stderr)
    assert process.returncode == 0 and not stderr, stderr.decode("utf-8", "replace")
    assert len(stdout) <= 1048576
    receipt = json.loads(stdout)
    assert receipt["gate_id"] == gate["id"] and receipt["test_passed"] is True
    assert receipt["probe_variant"] == variant
    assert receipt["selection"] == selected and receipt["identity"] == identity
    assert receipt["instrumented_owner_probe"] is True and receipt["daemon_or_native_client_executed"] is False
    assert receipt["claimed_daemon_payload_bytes"] == receipt["actual_provider_calls"] == 0
    assert receipt["closure"]["owner_exited"] is receipt["closure"]["descriptors_closed"] is True
    assert len(set(receipt["topology"]["networks"].values())) == 6
    for snapshot in receipt["snapshots"]:
        ledger.validate_snapshot(snapshot["ledger"], messages=snapshot["messages"], selected=selected, identity=identity)
    return receipt, hashlib.sha256(helper_bytes).hexdigest()


@pytest.mark.parametrize("gate", INSTRUMENTED, ids=[row["id"] for row in INSTRUMENTED])
def test_private_owner_channel_gate(tmp_path, record_property, owner_runtime, gate):
    if gate["name"] == "overlap_concurrency":
        receipts, helper_digests = [], []
        for variant, role, reason in (("same_role", "dns_frontend", "concurrent_connection_limit"),
                                      ("cross_role", "http_frontend", "action_role_changed")):
            directory = tmp_path / variant
            directory.mkdir(mode=0o700)
            receipt, helper_digest = _private_owner_trial(directory, owner_runtime, gate, variant)
            exchange = receipt["observations"]["last_exchange"]
            before, after = [row["ledger"] for row in receipt["snapshots"][-2:]]
            assert exchange["role"] == role
            assert exchange["message"]["operation"] == "RESERVE_CONNECTION"
            assert exchange["reply"]["status"] == "denied" and exchange["reply"]["reason"] == reason
            assert after["terminal_reason"] == reason and after["counters"] == before["counters"]
            assert before["counters"]["connections"] == 1
            assert before["counters"]["request_bytes"] == before["counters"]["response_bytes"] == 0
            receipts.append(receipt)
            helper_digests.append(helper_digest)
        assert receipts[0]["identity"]["owner_identity_sha256"] != receipts[1]["identity"]["owner_identity_sha256"]
        assert helper_digests[0] == helper_digests[1]
        helper_digest = helper_digests[0]
        record_property("private_owner_trials", 2)
    else:
        _, helper_digest = _private_owner_trial(tmp_path, owner_runtime, gate)
    record_property("gate_id", gate["id"])
    record_property("helper_sha256", helper_digest)
    record_property("case_passed", True)
    record_property("useful_daemon_claim", False)


@pytest.mark.parametrize("gate_id", ("owner/A/B15", "owner/A/B16"))
def test_actual_owner_or_foreign_grant(tmp_path, terminal, record_property, gate_id):
    report = _n15_composite(tmp_path, "A", terminal)
    assert report["case_passed"] is True
    composite = json.loads((tmp_path / "n15-composite.json").read_bytes())
    index = 0 if gate_id.endswith("15") else 1
    assert composite["attempts"][index]["kind"] == ("closed_owner" if index == 0 else "cross_configuration_live_donor")
    record_property("gate_id", gate_id)
    record_property("case_passed", True)
    record_property("test_authority", "scripted_owned_pty")


@pytest.mark.parametrize("gate_id,step,source", (("owner/A/B18", 2, "owner_arm"), ("owner/A/B19", 3, "owner_terminal")))
def test_actual_expired_binding(tmp_path, record_property, gate_id, step, source):
    directory = tmp_path / "trial"
    report = diagnostic.run_trial(directory, configuration="A", case="N14", execute=True, unattended_owned_lab_test=True)
    assert report["case_passed"] and report["expected_negative"] and evidence.inspect_trial(directory) == report
    result = json.loads((directory / f"result-{step}.json").read_bytes())
    refusal = result["name_tls_refusal"]
    assert refusal["source"] == source and refusal["reason"] == "binding_expired"
    assert result["name_tls_ledger"]["counters"]["actions"] == result["name_tls_ledger"]["counters"]["connections"] == 1
    assert result["bytes_received"] == 0 and result["tool_observation"] is None
    record_property("gate_id", gate_id)
    record_property("case_passed", True)


@pytest.mark.parametrize("slot,gate_id", (("http", "owner/A/B20"), ("tls", "owner/A/B21")))
def test_actual_second_dns_invalidates_reviewed_service(tmp_path, monkeypatch, terminal, record_property, slot, gate_id):
    import base64
    from name_tls_binding_witness import install as install_binding_witness, validate as validate_binding_witness
    instrumentation = install_binding_witness(tmp_path, monkeypatch, slot)
    with NativeSession(tmp_path / "session", "A", "N1", evidence=False) as session:
        sources_by_module = {row["module"]: row["sha256"] for row in session.manifest["runtime"]["python_sources"]["files"]}
        assert all(sources_by_module[row["module"]] == row["instrumented_sha256"]
                   for row in instrumentation["source_variants"])
        first = session.submit("dns_1", terminal=terminal)
        assert first["execution_status"] == "succeeded"
        original_binding = deepcopy(first["untrusted_result"]["name_tls_ledger"]["binding"])
        stale = contract.service_action(session.selected, session.lab.identity, slot, original_binding)
        review = _scripted_review(session.approvals, stale, session.policy, terminal, session.control)
        second = session.submit("dns_2", terminal=terminal)
        result = second["untrusted_result"]
        assert second["execution_status"] == "succeeded" and result["tool_observation"]["expected_negative"]
        state = result["name_tls_ledger"]
        ledger.validate_snapshot(state, messages=result["name_tls_messages"])
        assert state["binding"] is None and state["observation_generation"] == 2
        assert state["terminal"] and state["terminal_reason"] == "declared_negative_completed"
        assert len(instrumentation["frames"]) == 1
        witness = validate_binding_witness(instrumentation["frames"][0], stale, result)
        before = _acknowledged_state(session)
        attempt = session.controller.submit(stale, execute=True, interactive=True, approval_reference=review["reference"],
                                            execution_control=session.control, session_step=3)
        assert attempt["execution_status"] == "blocked" and attempt["reasons"] == ["isolation_unavailable"]
        assert attempt["approval_reference"] == review["reference"] and "untrusted_result" not in attempt
        assert session.approvals.consume(review["reference"], parse_action(stale), session.policy) == "approval_unknown_or_replayed"
        after = _acknowledged_state(session)
        assert before == after and before["launcher_alive"]
        closure = session.close_owner()
        events = [json.loads(line) for line in (session.directory / "audit.jsonl").read_bytes().splitlines()]
        attempt_events = [event for event in events if event["session_step"] == 3]
        assert [row["event_type"] for row in attempt_events] == ["policy_decision", "approval_consumed", "execution_blocked"]
        receipt = {"schema_version": "1", "gate_id": gate_id, "test_authority": "scripted_owned_pty",
            "manifest": session.manifest, "dns_outcomes": session.outcomes, "stale_proposal": stale,
            "review": review, "attempt": attempt, "before": before, "after": after, "closure": closure,
            "approval_messages": session.approval_messages, "audit_events": events,
            "guard": "static_profile_after_owner_generation_invalidation", "service_native_launches": 0,
            "owner_guard_witness": witness,
            "instrumentation": {key: value for key, value in instrumentation.items() if key != "frames"},
            "witness_frame_base64": base64.b64encode(instrumentation["frames"][0]).decode("ascii"),
            "previously_executable_n1_service_claim": False, "approval_store_revocation_claim": False}
        raw = json.dumps(receipt, sort_keys=True, allow_nan=False).encode("ascii")
        assert len(raw) <= 1048576
        save(tmp_path / "native-stale-grant.json", raw)
    record_property("gate_id", gate_id)
    record_property("case_passed", True)
    record_property("test_authority", "scripted_owned_pty")
