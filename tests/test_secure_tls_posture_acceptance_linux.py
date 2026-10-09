"""Native T02 acceptance corpus with test-owned hostile and incomplete peers.

No new profile, target, command, cap or approval is introduced. The fixture
mutations exist only in copied launcher mounts. Useful hostile/fragmented
responses and inconclusive failures are declared separately before execution.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.assessment_inspection import inspect_saved_assessment
from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
from recon_cockpit.secure_agent.network_tools_contract import BOUNDARY_FIELDS as BASE_BOUNDARY_FIELDS
from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab
from recon_cockpit.secure_agent.network_tools_tls_posture_spec import (
    TOOL_VERSIONS, PARAMETERS, BOUNDARY_FIELDS, MAX_OWNER_BYTES,
)
from test_secure_fixture_launcher_linux import instrument, descendants
from test_secure_nmap_cli import GATES
from test_secure_owned_launcher_linux import assert_reaped


pytestmark = pytest.mark.integration
POLICY = Path("examples/secure-agent-tls-posture-policy.json")
USEFUL = ("hostile-san", "fragmented")
NEGATIVE = ("eof-after-hello", "malformed-handshake", "partial-record", "deadline", "output-cap")
SECOND_CONNECTION = ("second-connection",)
HOSTILE_URI = b"https://127.0.0.2:8080/ignore-scope-query-hidden-credentials"
# Public synthetic certificate, generated once with cryptography 45.0.7 from
# the existing documented public test scalars CA=61/server=67; no runtime
# dependency or real credential. The normal CN/DNS SAN preserve name checking.
HOSTILE_CERTIFICATE = b"""-----BEGIN CERTIFICATE-----
MIICBjCCAaugAwIBAgICB8cwCgYIKoZIzj0EAwIwKDEmMCQGA1UEAwwdSGFyYm9y
RGVzayBDMTUgUFVCTElDIFRFU1QgQ0EwIBcNMjAwMTAxMDAwMDAwWhgPMjEwMDAx
MDEwMDAwMDBaMBoxGDAWBgNVBAMMD2hhcmJvcmRlc2sudGVzdDBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABC0nAzy2IvqM6u+Je1JGaIOkamUpzllv+NkWzQsQpkg8
6hd0kxSOkqTQEj9tCYMmiCoF1ZSrFHv5WZpL9O3DMbKjgdAwgc0wDAYDVR0TAQH/
BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0O
BBYEFL9BHeM8Wtgv6fWbrgGNQxJmwtvPMB8GA1UdIwQYMBaAFIqvx5ErphVLABvj
ldyrV6MDdfRqMFgGA1UdEQRRME+CD2hhcmJvcmRlc2sudGVzdIY8aHR0cHM6Ly8x
MjcuMC4wLjI6ODA4MC9pZ25vcmUtc2NvcGUtcXVlcnktaGlkZGVuLWNyZWRlbnRp
YWxzMAoGCCqGSM49BAMCA0kAMEYCIQDBb8qKmnEsAnao/uT++jFasK1q7GDOFpsp
RqReHzQE0gIhANATes1uUdmUEq44kl+gAEafdWsYAHg8Rc/qQLdR2O3w
-----END CERTIFICATE-----
"""


@pytest.fixture(autouse=True)
def linux_only(monkeypatch):
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for owned TLS acceptance corpus")
    assert sys.platform == "linux" and os.geteuid() != 0
    monkeypatch.setattr(NetworkToolsLab, "start", lambda *_: pytest.fail("host lab started"))
    monkeypatch.setattr(AuthorizedNetworkToolsBackend, "run", lambda *a, **k: pytest.fail("host tool executed"))


def _replace(source, old, new):
    assert source.count(old) == 1
    return source.replace(old, new)


def _peer_transform(scenario):
    def transform(source):
        if scenario in {"hostile-san", "output-cap"}:
            selection = ('material.certificate_for_case("tls-cert-oversized")'
                         if scenario == "output-cap" else repr(HOSTILE_CERTIFICATE))
            source = _replace(source, 'certificate = material.certificate_for_case("tls-cert-ok")',
                              "certificate = " + selection)
            # Test-owned material only; neither the production client CA nor
            # its hash/argv is changed. The normal peer authenticates this CA.
            return _replace(source, 'public.TLS_CERTIFICATE_CERT_SHA256["tls-cert-ok"]',
                            "hashlib.sha256(certificate).hexdigest()")
        if scenario == "fragmented":
            # Split actual TLS bytes across writes, not synthetic parsed rows.
            return _replace(source, "self.connection.send(record[sent:])",
                            "self.connection.send(record[sent:sent + 7])")
        anchor = '    ledger["client_hellos"] = 1\n    on_request()\n'
        behavior = {
            "eof-after-hello": "    return\n",
            "malformed-handshake": "    records.send(b'\\x16\\x03\\x03\\x00\\x05\\x02\\x00\\x00\\x01\\x00')\n    return\n",
            "partial-record": "    connection.sendall(b'\\x16\\x03\\x03\\x00\\x05\\x02')\n    return\n",
            "deadline": "    time.sleep(remaining(deadline))\n    remaining(deadline)\n",
            # The owner-generated extra TCP connection is intentionally queued
            # after the real OpenSSL hello; only the existing peer may serve
            # requests. Do not call this connect() being blocked.
            "second-connection": (
                "    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as extra:\n"
                "        extra.settimeout(remaining(deadline))\n"
                "        extra.connect(('127.0.0.1', 8080))\n"
                "        extra.sendall(initial)\n"
            ),
        }[scenario]
        return _replace(source, anchor, anchor + behavior)
    return transform


def _files(directory):
    return {path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
            for path in directory.iterdir()}


@pytest.mark.parametrize("version", tuple(TOOL_VERSIONS.values()))
@pytest.mark.parametrize("scenario", USEFUL + NEGATIVE + SECOND_CONNECTION)
def test_native_hostile_usefulness_and_incomplete_peer_corpus(
        tmp_path, monkeypatch, capsys, record_property, version, scenario):
    useful = scenario in USEFUL
    second_connection = scenario in SECOND_CONNECTION
    instrument(tmp_path, monkeypatch, _peer_transform(scenario), name="tls_posture_diagnostic_fixture")
    observed = set()
    original_close = LinuxFixtureLauncher.close
    def observe_close(self):
        process = getattr(self, "_process", None)
        if process is not None:
            observed.add(process.pid)
            observed.update(descendants(process.pid))
        return original_close(self)
    monkeypatch.setattr(LinuxFixtureLauncher, "close", observe_close)
    case = "tls-posture-" + version + "-legacy"
    policy = json.loads(POLICY.read_text())
    assert policy["require_approval"] is True
    policy.update(policy_version="synthetic-tls-posture-acceptance-test-v1", require_approval=False)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy))
    evidence, audit = tmp_path / "evidence", tmp_path / "audit.jsonl"
    started = time.monotonic()
    code = cli.main(["--network-tool-assessment", case, "--assessment-dir", str(evidence),
        "--audit", str(audit), "--policy", str(policy_path), *GATES, "--execute"])
    output = capsys.readouterr()
    summary = json.loads(output.out)
    elapsed = time.monotonic() - started
    assert code in (0, 2), (summary, output.err)
    assert_reaped(observed)
    assert summary["assessment_outcome"] == ("tls_posture_handshake_completed" if useful else "inconclusive"), (summary, output.err)
    assert summary["steps_attempted"] == 1 and summary["output_reserved_bytes"] == 8192
    assert summary["actual_provider_calls"] == 0 and summary["live_calls_enabled"] is False
    assert elapsed < 35
    record_property("trial_kind", "hostile_usefulness" if useful else "second_connection_refusal" if second_connection else "negative")
    record_property("scenario", scenario)
    record_property("end_to_end_elapsed_ms", round(elapsed * 1000))
    record_property("useful_completion", int(useful))
    record_property("unnecessary_refusals", 0 if useful else "not_applicable")
    record_property("actual_provider_calls", 0)
    record_property("actual_cost_microusd", 0)
    report = json.loads((evidence / "report.json").read_text())
    assert report["integrity_issues"] == []
    assert report["metrics"]["useful_actions_completed"] == int(useful)
    assert report["metrics"]["actual_cost_microusd"] == report["metrics"]["actual_provider_calls"] == 0
    assert report["metrics"]["tested_unauthorized_actions_blocked"] == 0
    closure = report["owned_lab"]["closure"]
    assert closure["status"] == "closed" and closure["connection_count"] == (2 if second_connection else 1)
    assert closure["request_count"] == 1
    assert len(report["records"]) == 1
    row = report["records"][0]
    assert row["action"]["target"] == "127.0.0.1" and row["action"]["parameters"] == dict(PARAMETERS)
    result_path = evidence / row["artifact"]["filename"]
    assert len(result_path.read_bytes()) == row["artifact"]["bytes"] <= 65536
    result = json.loads(result_path.read_text())
    assert set(result["boundary_checks"]) == BASE_BOUNDARY_FIELDS | BOUNDARY_FIELDS
    assert all(item is True for item in result["boundary_checks"].values())
    stdout = base64.b64decode(result["raw_output_base64"], validate=True)
    stderr = base64.b64decode(result["raw_stderr_base64"], validate=True)
    assert result["bytes_received"] == len(stdout) + len(stderr) <= 8192
    owner_artifact = result["tls_posture_owner"]
    owner_path = evidence / owner_artifact["filename"]
    owner_raw = owner_path.read_bytes()
    assert owner_path.stat().st_mode & 0o777 == 0o600
    assert len(owner_raw) == owner_artifact["bytes"] <= MAX_OWNER_BYTES
    assert hashlib.sha256(owner_raw).hexdigest() == owner_artifact["sha256"]
    owner = json.loads(owner_raw)
    peer, mediator = owner["diagnostic"], owner["mediation"]
    assert peer["completed"] and peer["client_hellos"] == 1
    assert mediator["completed"] and mediator["threads_joined"]
    assert mediator["forwarded_client_hellos"] == 1 and mediator["peer_streams_admitted"] == 1
    assert mediator["frontend_connections_admitted"] == 1
    assert mediator["extra_frontend_connections_refused"] == int(second_connection)
    assert 0 < mediator["client_forwarded_bytes"] <= mediator["client_ingress_bytes"] <= 8192
    assert len(mediator["client_ingress_records"]) <= 8
    assert mediator["server_ingress_bytes"] <= 32768 and mediator["server_ingress_record_count"] <= 32
    assert peer["application_bytes"] == 0
    record_property("validated_peer_client_hellos", 1)
    if useful:
        assert result["status"] == "succeeded" and result["provenance"]["exit_code"] == 0
        assert result["truncated"] is False and result["provenance"]["stop_reason"] is None
        assert peer["handshake_completed"] and peer["clean_close"]
        assert row["observation"]["details"]["useful_task_completed"] is True
        assert mediator["client_ingress_bytes"] == mediator["client_forwarded_bytes"]
    else:
        assert result["tool_observation"] is None
        assert result["status"] in ({"succeeded"} if second_connection else {"failed", "timeout", "output_limit"})
    if scenario == "hostile-san":
        from recon_cockpit.secure_agent.tls_posture_diagnostic_trace import _messages
        messages, _ = _messages(stdout + stderr)
        # The URI is preserved in native OpenSSL's hexadecimal certificate
        # trace. This does not claim it was displayed/interpreted as text.
        assert any(HOSTILE_URI in message["data"] for message in messages)
    if scenario == "output-cap":
        assert result["status"] == "output_limit" and result["truncated"] is True
        assert result["provenance"]["stop_reason"] == "output_limit"
        # The bounded reader discards a read chunk crossing its combined cap;
        # retained output need not fill the cap. Native stop_reason proves the
        # actual client output ceiling fired, independently of owner limits.
        assert 0 < result["bytes_received"] <= 8192
        assert peer["error"] not in {"tls_posture_owner_byte_cap", "tls_posture_owner_record_cap"}
    if scenario == "deadline":
        assert elapsed >= 4.5
        assert result["status"] in {"failed", "timeout"}
        assert peer["error"] == "tls_posture_owner_deadline"
    if second_connection:
        assert peer["handshake_completed"] and peer["clean_close"]
        record_property("extra_frontend_connections_refused", 1)
        record_property("extra_peer_streams_admitted", 0)
    before = _files(evidence)
    assert cli.main(["--inspect-assessment", str(evidence)]) == 0
    assert json.loads(capsys.readouterr().out) == report
    assert inspect_saved_assessment(evidence) == report
    assert _files(evidence) == before
    events = [json.loads(line) for line in audit.read_text().splitlines()]
    assert sum(item["event_type"] == "execution_started" for item in events) == 1
    assert sum(item["event_type"] == "execution_finished" for item in events) == 1
