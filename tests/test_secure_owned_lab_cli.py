"""Owned lab CLI wiring with explicit process doubles, not kernel evidence."""

import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import cli, coordinator_isolation, openai_provider
from recon_cockpit.secure_agent.evidence import inspect_assessment
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.openai_protocol import build_request, decode_response
from recon_cockpit.secure_agent.owned_lab_contract import BACKEND, identity
from recon_cockpit.secure_agent.worker import _response


@pytest.mark.parametrize("options", [
    ["--mock"], ["--http-assessment", "a", "--assessment-dir", "unused"],
    ["--discovery-assessment", "a", "--assessment-dir", "unused"],
    ["--inspect-assessment", "unused"], ["--workflow-assessment", "a"],
    ["--workflow-assessment", "a", "--assessment-dir", "unused", "--fixture"],
    ["--workflow-assessment", "a", "--assessment-dir", "unused", "--routed"],
])
def test_owned_lab_invalid_combinations_fail_before_reading_policy(monkeypatch, options):
    monkeypatch.setattr(cli, "_read_bounded", lambda *_: pytest.fail("must not read policy"))
    with pytest.raises(SystemExit) as exc:
        cli.main(["--owned-lab", *options])
    assert exc.value.code == 2


@pytest.fixture
def doubles(monkeypatch):
    from recon_cockpit.secure_agent import owned_lab

    labs = []

    class Lab:
        def __init__(self, case, session_id, limits, *, execute):
            self.identity = identity(case, str(uuid4()))
            self.started = False
            self.closed = False
            self.calls = self.requests = 0
            labs.append(self)

        def __enter__(self):
            return self

        def close(self):
            self.closed = True
            return {"identity": self.identity, "status": "closed",
                    "connection_count": self.calls, "request_count": self.requests}

        def __exit__(self, *_):
            self.close()

    class Backend:
        name = BACKEND

        def __init__(self, policy, session_id, limits, lab, *, execute):
            self.lab = lab

        def check_available(self, action=None):
            pass

        def run(self, action, policy, *, control):
            control.check()
            assert not self.lab.closed
            self.lab.started = True
            self.lab.calls += 1
            if action.tool_id == "tcp_connect":
                value = {"status": "succeeded", "results": [
                    {"target": "127.0.0.1", "port": 8080, "state": "open"}],
                    "bytes_received": 0, "truncated": False}
            else:
                self.lab.requests += 1
                status, body, _ = _response(action.parameters.path)
                count = len(body) + 64
                value = {"status": "succeeded", "bytes_received": count, "truncated": False,
                         "results": [{"target": action.target, "port": 8080, "http_status": status,
                                      "body": body.decode(), "bytes_received": count, "truncated": False,
                                      "response_sha256": hashlib.sha256(body).hexdigest()}]}
            return {**value, "backend": self.name,
                    "owned_lab": {"identity": self.lab.identity, "connection_count": self.lab.calls,
                                  "request_count": self.lab.requests}}

    class Parser:
        boundary_checks = None

        def plan(self, config, observation, exchange, *, control):
            return decode_response(exchange(build_request(config, observation), control=control))

    def coordinate(self, init, exchange, *, control):
        initial = json.loads(init)
        for step in range(1, 5):
            request = {**initial, "sequence": step, "operation": "plan"}
            for _ in range(2):
                response = json.loads(exchange(json.dumps(request).encode(), control=control))
                if response["stop"]:
                    return json.dumps({**initial, "status": "closed"}).encode()
                request.update(operation="propose", plan=response["plan"])
        pytest.fail("authority did not stop")

    monkeypatch.setattr(owned_lab, "OwnedLab", Lab)
    monkeypatch.setattr(owned_lab, "AuthorizedOwnedLabBackend", Backend)
    monkeypatch.setattr(openai_provider, "LinuxOpenAIPlanner", Parser)
    monkeypatch.setattr(coordinator_isolation.LinuxOfflineCoordinator, "run", coordinate)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    return labs


def arguments(tmp_path, *, approval=False):
    policy = json.loads((Path(__file__).resolve().parents[1] /
                         "examples/secure-agent-discovery-policy.json").read_text())
    policy["require_approval"] = approval
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    return ["--workflow-assessment", "a", "--owned-lab", "--policy", str(path),
            "--assessment-dir", str(tmp_path / "evidence"), "--audit", str(tmp_path / "audit/events.jsonl")]


@pytest.mark.parametrize("mode,calls,exit_code", [
    ("execute", 3, 0), ("dry", 0, 0), ("approval", 0, 2), ("budget", 0, 2),
])
def test_owned_lab_cli_closes_before_finalization_and_preserves_mode(
        tmp_path, capsys, doubles, mode, calls, exit_code):
    args = arguments(tmp_path, approval=mode == "approval")
    args += ["--dry-run"] if mode == "dry" else ["--execute"]
    if mode == "budget":
        args += ["--session-max-output-bytes", "1"]
    assert cli.main(args) == exit_code
    output = json.loads(capsys.readouterr().out)
    lab, = doubles
    assert lab.closed and lab.started == (calls > 0) and lab.calls == calls
    assert output["workflow_card"]["version"] == "2"
    assert output["owned_lab"]["identity"] == lab.identity
    assert output["owned_lab"]["closure"] == lab.close()
    assert output["assessment_outcome"] == ("validated" if calls else "inconclusive")
    assert output["live_calls_enabled"] is False
    report = inspect_assessment(tmp_path / "evidence")
    assert report["integrity_issues"] == [] and report["owned_lab"] == output["owned_lab"]


def test_owned_lab_cleanup_failure_never_finalizes_a_positive_report(tmp_path, capsys, doubles, monkeypatch):
    from recon_cockpit.secure_agent import owned_lab

    def fail(self):
        self.closed = True
        raise IsolationUnavailable("PRIVATE cleanup failure")

    monkeypatch.setattr(owned_lab.OwnedLab, "close", fail)
    assert cli.main([*arguments(tmp_path), "--execute"]) == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out)["reasons"] == ["isolation_unavailable"]
    assert "PRIVATE" not in captured.out + captured.err
    assert not (tmp_path / "evidence/report.json").exists()
    assert inspect_assessment(tmp_path / "evidence")["outcome"] == "inconclusive"
