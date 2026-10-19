"""36 fixed A-only native authority mutations, with real audit/approval peers.

Source instrumentation observes actual refusal points or removes/mutates a
real proof. It never substitutes a successful owner, grant or native result.
"""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import pytest

from recon_cockpit.secure_agent import launcher_protocol
from recon_cockpit.secure_agent import name_tls_contract as contract
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import parse_action
from recon_cockpit.secure_agent.name_tls_lab import NameTLSLab
from test_name_tls_linux import NativeSession, _scripted_review, terminal
from test_secure_approval_linux import instrument_worker
from test_secure_audit_witness import intent
from test_secure_fixture_launcher_linux import instrument

pytestmark = pytest.mark.integration
MUTATIONS = ("missing_audit", "changed_action_audit", "missing_approval", "changed_action_approval",
             "changed_policy", "changed_session", "expired_approval", "consumed_approval_replay",
             "missing_admission", "changed_runtime/binding_launch_commitment", "direct_backend_bypass",
             "direct_witnessed_negative_then_later_action")


@pytest.fixture(autouse=True)
def owned_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned name/TLS authority gates")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(NameTLSLab, "start", lambda *_a, **_kw: pytest.fail("host topology fallback"))


def _instrument_launcher(tmp_path, monkeypatch, operation, mutation):
    target = contract.TOOL_IDS[operation]
    def transform(source):
        for reader, marker in (("witness_reader", "AUDIT"), ("approval_reader", "APPROVAL")):
            original = f"                    {reader}.require(config, action, control)"
            assert source.count(original) == 1
            source = source.replace(original,
                "                    try:\n"
                f"                        {reader}.require(config, action, control)\n"
                "                    except ValueError as error:\n"
                f"                        if action.tool_id == {target!r}:\n"
                f"                            os.write(2, b'EXPECTED-NAME-TLS-{marker}:' + str(error).encode('ascii'))\n"
                "                        raise")
        gate_line = "                granted = gate.admit(action, policy, control=control)"
        assert source.count(gate_line) == 1
        if mutation in MUTATIONS[:8]:
            source = source.replace(gate_line,
                f"                if action.tool_id == {target!r}:\n"
                "                    os.write(2, b'UNEXPECTED-NAME-TLS-ADMISSION')\n"
                "                    raise ValueError('name_tls_witness_tripwire')\n" + gate_line)
        if mutation == "missing_admission":
            original = ("                if granted['reason'] is not None or gate.redeem(granted['permit'], action, policy, control=control)['reason'] is not None:\n"
                        "                    raise ValueError('launcher_admission_denied')")
            assert source.count(original) == 1
            source = source.replace(original,
                f"                supplied_permit = None if action.tool_id == {target!r} else granted['permit']\n"
                "                redemption = gate.redeem(supplied_permit, action, policy, control=control)\n"
                "                if granted['reason'] is not None or redemption['reason'] is not None:\n"
                "                    os.write(2, b'EXPECTED-NAME-TLS-ADMISSION:' + str(redemption['reason']).encode('ascii'))\n"
                "                    raise ValueError('launcher_admission_denied')")
        if mutation == "changed_runtime/binding_launch_commitment":
            original = "                result = (owned.run(action, policy, control=control) if owned is not None else"
            assert source.count(original) == 1
            field = "runtime_identity_sha256" if operation == "dns" else "binding_sha256"
            source = source.replace(original,
                f"                if action.tool_id == {target!r}:\n"
                "                    from recon_cockpit.secure_agent import name_tls_contract as nc\n"
                "                    changed = action.parameters.to_dict()\n"
                f"                    changed[{field!r}] = '0' * 64\n"
                "                    action = nc.parse_action(nc._action(config['case'], owned.lab.identity, changed['operation_slot'], changed))\n"
                "                    os.write(2, b'EXPECTED-NAME-TLS-COMMITMENT-ATTEMPT')\n" + original)
        compiled = compile(source, "owned-name-tls-witness-launcher", "exec")
        assert compiled is not None
        return source
    instrument(tmp_path, monkeypatch, transform)


def _instrument_approval(tmp_path, monkeypatch, operation, mutation):
    target = contract.TOOL_IDS[operation]
    if mutation not in ("changed_action_approval", "expired_approval", "consumed_approval_replay"):
        return
    def transform(source):
        original = "                    encoded = protocol.encode(proof)"
        assert source.count(original) == 1
        if mutation == "changed_action_approval":
            source = source.replace(original,
                f"                    if action.tool_id == {target!r}:\n"
                "                        proof['action_digest'] = '0' * 64\n" + original)
        elif mutation == "expired_approval":
            # Shorten the actual worker's consumed proof, then let the real
            # monotonic clock expire it; never extend the original grant.
            source = source.replace(original,
                f"                    if action.tool_id == {target!r}:\n"
                "                        proof['expires_at'] = min(proof['expires_at'], time.monotonic() + .25)\n" + original)
        else:
            original = "                    witness_sequence += 1"
            assert source.count(original) == 1
            source = source.replace(original,
                f"                    if action.tool_id == {target!r}:\n"
                "                        if os.write(witness_channel.fileno(), encoded) != len(encoded):\n"
                "                            raise ValueError('name_tls_proof_replay_short_write')\n" + original)
        compile(source, "owned-name-tls-approval-mutation", "exec")
        return source
    instrument_worker(tmp_path, monkeypatch, transform)


def _ready(session):
    if session.backend.boundary_checks is None:
        session.backend._start(session.control)
    assert session.backend.boundary_checks == dict.fromkeys(launcher_protocol.CHECKS, True)
    assert session.backend._process.poll() is None


def _witnessed_direct(session, raw, terminal):
    review = _scripted_review(session.approvals, raw, session.policy, terminal, session.control)
    action = parse_action(raw)
    assert session.approvals.consume(review["reference"], action, session.policy) is None
    event = intent(action, session.policy, session.session_id, backend=contract.BACKEND)
    event["approval_reference"] = review["reference"]
    session.audit.emit(event)
    return session.backend.run(action, session.policy, control=session.control)


def _terminal_then_later(tmp_path, operation, terminal):
    case = {"dns": "N2", "http": "N14", "tls": "N11"}[operation]
    with NativeSession(tmp_path / "trial", "A", case, evidence=False) as session:
        dns = session.submit("dns_1", terminal=terminal)
        assert dns["execution_status"] == "succeeded", dns
        if operation == "dns":
            previous = dns["untrusted_result"]
            later = session.action("dns_1")
        else:
            assert dns["untrusted_result"]["name_tls_ledger"]["binding"] is not None
            if operation == "http":
                binding = dns["untrusted_result"]["name_tls_ledger"]["binding"]
                expiry = session.control.deadline - 60 + binding["expires_at_us"] / 1000000
                while time.monotonic() <= expiry:
                    session.control.check()
                    time.sleep(.01)
            previous = _witnessed_direct(session, session.action(operation), terminal)
            later = session.action("tls")
        assert previous["name_tls_ledger"]["terminal"] is True
        counters = deepcopy(previous["name_tls_ledger"]["counters"])
        if operation == "http":
            assert previous["name_tls_refusal"]["reason"] == "binding_expired"
            refused = _witnessed_direct(session, later, terminal)
            assert refused["status"] == "blocked" and refused["name_tls_refusal"]["source"] == "owner_terminal"
            assert refused["name_tls_ledger"]["counters"] == counters
        else:
            with pytest.raises(IsolationUnavailable):
                _witnessed_direct(session, later, terminal)
            assert session.backend._closed and session.backend._process.poll() is not None
        closure = session.close_owner()
        assert closure["last_result"]["connection_count"] == counters["connections"]
        return {"terminal_reason": previous["name_tls_ledger"]["terminal_reason"],
                "last_acknowledged_counters": counters, "closure": closure}


@pytest.mark.parametrize("operation", ("dns", "http", "tls"))
@pytest.mark.parametrize("mutation", MUTATIONS)
def test_native_authority_witness(tmp_path, monkeypatch, terminal, record_property, operation, mutation):
    gate_id = f"authority/A/{operation}/{mutation}"
    if mutation == "direct_witnessed_negative_then_later_action":
        receipt = _terminal_then_later(tmp_path, operation, terminal)
    else:
        _instrument_launcher(tmp_path, monkeypatch, operation, mutation)
        _instrument_approval(tmp_path, monkeypatch, operation, mutation)
        with NativeSession(tmp_path / "trial", "A", "O4", evidence=False) as session:
            if operation != "dns":
                prerequisite = session.submit("dns_1", terminal=terminal)
                assert prerequisite["execution_status"] == "succeeded", prerequisite
                assert prerequisite["untrusted_result"]["name_tls_ledger"]["binding"] is not None
            raw = session.action("dns_1" if operation == "dns" else operation)
            action = parse_action(raw)
            review = _scripted_review(session.approvals, raw, session.policy, terminal, session.control)
            _ready(session)
            before, prior = dict(session.backend.snapshot), deepcopy(session.backend._lab_context)
            if mutation == "direct_backend_bypass":
                with pytest.raises(IsolationUnavailable, match="requires the witnessed isolated launcher"):
                    session.original.run(action, session.policy, control=session.control)
                assert dict(session.backend.snapshot) == before and session.backend._lab_context == prior
                assert session.backend._process.poll() is None
                marker = "host_backend_type_guard"
            else:
                if mutation != "missing_approval":
                    assert session.approvals.consume(review["reference"], action, session.policy) is None
                event = intent(action, session.policy, session.session_id, backend=contract.BACKEND)
                event["approval_reference"] = review["reference"]
                if mutation == "changed_action_audit":
                    event["action_digest"] = "0" * 64
                elif mutation == "changed_policy":
                    event["policy_digest"] = "0" * 64
                elif mutation == "changed_session":
                    event["session_id"] = "00000000-0000-0000-0000-000000000000"
                if mutation != "missing_audit":
                    session.audit.emit(event)
                if mutation == "expired_approval":
                    time.sleep(.35)
                with pytest.raises(IsolationUnavailable):
                    session.backend.run(action, session.policy, control=session.control)
                assert session.backend._closed and session.backend._process.poll() is not None
                diagnostic = bytes(session.backend._supervisor.buffers["worker_err"])
                expected = ("AUDIT" if mutation in ("missing_audit", "changed_action_audit", "changed_policy", "changed_session")
                            else "ADMISSION" if mutation == "missing_admission"
                            else "COMMITMENT-ATTEMPT" if mutation == "changed_runtime/binding_launch_commitment" else "APPROVAL")
                assert ("EXPECTED-NAME-TLS-" + expected).encode("ascii") in diagnostic, diagnostic
                assert b"UNEXPECTED-NAME-TLS-ADMISSION" not in diagnostic
                if mutation == "missing_admission":
                    assert b"admission_missing" in diagnostic
                if mutation == "changed_runtime/binding_launch_commitment":
                    assert (b"Name/TLS proposal owner changed" in diagnostic if operation == "dns" else
                            b"name_tls_action_binding_changed" in diagnostic), diagnostic
                assert dict(session.backend.snapshot) == before and session.backend._lab_context == prior
                marker = diagnostic.decode("ascii", "replace")
            receipt = {"guard": marker, "before": before, "after": dict(session.backend.snapshot),
                       "last_acknowledged_context": prior, "closure": session.close_owner()}
    record_property("gate_id", gate_id)
    record_property("case_passed", True)
    files = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in tmp_path.glob("*.py")}
    (tmp_path / "authority-receipt.json").write_text(json.dumps({"schema_version": "1", "gate_id": gate_id,
        "instrumentation_sha256": files, "receipt": receipt}, sort_keys=True, ensure_ascii=True))
