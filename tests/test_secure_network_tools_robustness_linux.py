"""Actual bounded tools under cancellation, hostile output and private inputs.

Only owned fixture/worker code is instrumented. No tool runs on the host, and
synthetic unattended test policy does not claim a human approval or acceptance.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import time

import pytest

from recon_cockpit.secure_agent.control_plane import AuthoritySession
from recon_cockpit.secure_agent.controller import Controller
from recon_cockpit.secure_agent.coordinator_isolation import LinuxOfflineCoordinator
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.nmap_evidence import NmapEvidenceStore, inspect_evidence
from recon_cockpit.secure_agent.network_tools_runtime import manifest_digest
from recon_cockpit.secure_agent.network_tools_contract import validate_tool_result
from recon_cockpit.secure_agent.session_limits import SessionLimits
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
from recon_cockpit.secure_agent.network_tools_contract import LIMITS, action
from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab
from test_secure_fixture_launcher_linux import descendants, instrument
from test_secure_owned_launcher_linux import assert_reaped
from test_secure_network_tools_gates_linux import boundary


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned network-tool robustness")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, "run", lambda *a, **k: pytest.fail("host tool executed"))


class _FixedProposal:
    """Trusted test provider; its sole action still crosses every real gate."""

    def __init__(self, case):
        self.case = case
        self.session_id = None

    def bind_session(self, session_id):
        assert self.session_id is None
        self.session_id = session_id

    def propose(self, observation, *, control):
        control.check()
        assert json.loads(observation) == {"step": 1, "untrusted_observation": None}
        return json.dumps({"schema_version": "1", "action": action(self.case), "done": True},
                          sort_keys=True, separators=(",", ":")).encode("ascii")


@pytest.mark.parametrize("case,binary", [("openssl-stalled", b"/tool/openssl"), ("dig-stalled", b"/tool/dig"),
    ("ssh-stalled", b"/tool/ssh-keyscan"), ("ldap-stalled", b"/tool/ldapsearch")])
def test_cancellation_after_actual_exec_reaps_tree_and_retains_authority_reservation(tmp_path, case, binary):
    setup = ExecutionControl(time.monotonic() + 40)
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
                        seen |= command == binary
                    if seen:
                        break
                    time.sleep(0.01)
                assert seen and not pending.done(), "actual confined tool never reached its stalled run"
                runner.cancel()
                summary = pending.result(timeout=8)
            finally:
                runner.cancel()
            assert summary["stop_reason"] == "session_cancelled"
            assert summary["session_status"] == "stopped" and summary["actions_succeeded"] == 0
            assert summary["steps_attempted"] == 1 and summary["output_reserved_bytes"] == 8192
            assert launcher._closed and launcher._process.poll() is not None
            assert launcher.close()["status"] == "closed"
            # No completion receipt arrived; closure must not invent final
            # request totals or reset/restart authority to recover the budget.
            with pytest.raises(RuntimeError, match="session_already_used"):
                runner.run(execute=True)
        assert_reaped(observed)
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    reservations = [event for event in events if event["event_type"] == "session_output_reserved"]
    assert len(reservations) == 1 and reservations[0]["output_reserved_bytes"] == 8192
    assert sum(event["event_type"] == "execution_started" for event in events) == 1
    finished = [event for event in events if event["event_type"] == "execution_finished"]
    assert len(finished) == 1 and finished[0]["execution_status"] == "cancelled"


def _der(tag, body):
    size = len(body)
    length = bytes([size]) if size < 128 else bytes([0x80 | ((size.bit_length() + 7) // 8)]) + size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + body


def _der_parts(raw):
    parts, offset = [], 0
    while offset < len(raw):
        start, tag = offset, raw[offset]
        offset += 1
        size = raw[offset]
        offset += 1
        if size & 0x80:
            count = size & 0x7f
            size = int.from_bytes(raw[offset:offset + count], "big")
            offset += count
        parts.append((tag, raw[offset:offset + size], raw[start:offset + size]))
        offset += size
    assert offset == len(raw)
    return parts


def _oversized_subject_certificate():
    # Alter public fixture DER only. Its intentionally invalid signature must
    # be rejected; the long subject pressures OpenSSL's own error diagnostics.
    from recon_cockpit.secure_agent.web_tools_tls_fixture import UNTRUSTED_SERVER_CERT_PEM
    raw = base64.b64decode(b"".join(UNTRUSTED_SERVER_CERT_PEM.splitlines()[1:-1]))
    outer = _der_parts(_der_parts(raw)[0][1])
    fields = _der_parts(outer[0][1])
    original_subject = fields[5][1]
    ou = _der(0x31, _der(0x30, b"\x06\x03\x55\x04\x0b" + _der(0x0c, b"X" * 64)))
    fields[5] = (0x30, b"", _der(0x30, original_subject + ou * 160))
    raw = _der(0x30, _der(0x30, b"".join(field[2] for field in fields)) + b"".join(part[2] for part in outer[1:]))
    encoded = base64.b64encode(raw)
    return b"-----BEGIN CERTIFICATE-----\n" + b"\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64)) + b"\n-----END CERTIFICATE-----\n"


@pytest.mark.parametrize("case", ["dig-ok", "openssl-untrusted", "ldap-injected"])
def test_actual_tool_oversized_output_is_truncated_without_observation(tmp_path, monkeypatch, case):
    def oversized(source):
        if case == "ldap-injected":
            # Only the synthetic owner response is enlarged. The actual
            # ldapsearch process still has its original argv, output ceiling,
            # anonymous base-search scope and single authority reservation.
            original = 'values["description"] = (fixture.HOSTILE_NOTE,)'
            assert source.count(original) == 1
            assert source.count("if not size <= 4096:") == 1
            return source.replace(original, 'values["description"] = ("X" * 12000,)').replace(
                "if not size <= 4096:", "if not size <= 16000:")
        if case == "dig-ok":
            original = "reply = fixture.dns_response(self.case, query)"
            assert source.count(original) == 1
            answer = b"\xc0\x0c" + __import__("struct").pack("!HHIH", 1, 1, 60, 4) + b"\x7f\x00\x00\x01"
            txt = b"\xc0\x0c" + __import__("struct").pack("!HHIH", 16, 1, 60, 251) + b"\xfa" + b"X" * 250
            replacement = "reply = query[:2] + struct.pack('!HHHHH', 0x8400, 1, 1, 0, 48) + fixture.DNS_QUESTION + " + repr(answer + txt * 48)
            return source.replace(original, replacement)
        original = 'if hashlib.sha256(cert).hexdigest() != expected:'
        assert source.count(original) == 1
        cert = _oversized_subject_certificate()
        return source.replace(original, 'cert = ' + repr(cert) + "\n    expected = hashlib.sha256(cert).hexdigest()\n    " + original)
    instrument(tmp_path, monkeypatch, oversized, name="network_tools_lab_worker")
    control = ExecutionControl(time.monotonic() + 40)
    evidence = tmp_path / "evidence"
    with boundary(tmp_path, control, case=case, approval_required=False) as (audit, approvals, launcher, policy, session):
        digest = manifest_digest(launcher._network_tools_manifest)
        with NmapEvidenceStore(evidence, session_id=session, policy=policy, case=case,
                owned_lab=launcher.identity, workflow_profile="network_tools", runtime_sha256=digest,
                deadline=control.deadline) as store:
            store.record_decision(1, b'{"step":1,"untrusted_observation":null}')
            result = Controller(policy, audit, launcher, approvals, session_id=session, evidence=store).submit(
                action(case), execute=True, interactive=False, execution_control=control, session_step=1)
            assert result["execution_status"] == "output_limit", result
            captured = result["untrusted_result"]
            stdout = base64.b64decode(captured["raw_output_base64"], validate=True)
            stderr = base64.b64decode(captured["raw_stderr_base64"], validate=True)
            assert captured["truncated"] is True and captured["tool_observation"] is None
            assert captured["provenance"]["stop_reason"] == "output_limit"
            assert 0 <= captured["bytes_received"] == len(stdout) + len(stderr) <= 8192
            assert validate_tool_result(captured, tool_id=action(case)["tool_id"],
                execution_status="output_limit", runtime_sha256=digest) == (stdout, stderr)
            assert all(captured["boundary_checks"].values())
            assert captured["owned_lab"]["request_count"] == (0 if case == "openssl-untrusted" else 1)
            assert dict(launcher.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 8192}
            observed = descendants(launcher._process.pid) | {launcher._process.pid}
            closure = launcher.close()
            assert closure["status"] == "closed"
            store.record_lab_closed(closure)
            report = store.finalize({"session_id": session, "mode": "execute", "session_status": "completed",
                "stop_reason": "coordinator_done", "steps_attempted": 1, "actions_succeeded": 0,
                "output_reserved_bytes": 8192})
            assert report["outcome"] == "inconclusive" and report["integrity_issues"] == []
            assert_reaped(observed)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in evidence.iterdir()}
    assert inspect_evidence(evidence) == report
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in evidence.iterdir()}
    events = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert sum(event["event_type"] == "execution_started" for event in events) == 1
    assert [event["execution_status"] for event in events if event["event_type"] == "execution_finished"] == ["output_limit"]


@pytest.mark.parametrize("case", ["openssl-ok", "dig-ok", "ssh-ok", "ldap-ok"])
def test_tool_cannot_read_host_canary_bootstrap_source_or_authority_descriptors(tmp_path, monkeypatch, case):
    canary = tmp_path / "private-host-canary"
    secret = "NETWORK-TOOLS-PRIVATE-CANARY-ONLY"
    canary.write_text(secret)
    canary.chmod(0o600)
    monkeypatch.setenv("NETWORK_TOOLS_HOST_CANARY", secret)
    def check_private_inputs(source):
        original = 'os.execve(argv[0], argv, runtime.execution_environment(request["tool_id"]))'
        assert source.count(original) == 1
        checks = f"""if os.environ.get('NETWORK_TOOLS_HOST_CANARY') is not None:
            raise RuntimeError('unexpected_host_environment')
        for candidate in ({str(canary)!r}, '/app/recon_cockpit/secure_agent/network_tools_worker.py'):
            try:
                leaked = os.open(candidate, os.O_RDONLY)
            except OSError:
                pass
            else:
                os.close(leaked)
                raise RuntimeError('unexpected_private_file')
        for candidate in range(3, 128):
            try:
                os.fstat(candidate)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                raise RuntimeError('unexpected_authority_descriptor')
        {original}"""
        return source.replace(original, checks)
    instrument(tmp_path, monkeypatch, check_private_inputs, name="network_tools_worker")
    control = ExecutionControl(time.monotonic() + 40)
    with boundary(tmp_path, control, case=case, approval_required=False) as (audit, approvals, launcher, policy, session):
        result = Controller(policy, audit, launcher, approvals, session_id=session).submit(
            action(case), execute=True, interactive=False, execution_control=control)
        assert result["execution_status"] == "succeeded", result
        assert result["untrusted_result"]["tool_observation"] is not None
        assert secret not in json.dumps(result)
        assert dict(launcher.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 8192}
    assert secret not in (tmp_path / "audit.jsonl").read_text()
