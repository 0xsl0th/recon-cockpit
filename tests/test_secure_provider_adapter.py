"""The TLS foundation adapter releases bounded data and has no tool interface."""

import json
from pathlib import Path
import signal
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import provider_adapter
from recon_cockpit.secure_agent.openai_protocol import OpenAIConfig, build_request
from recon_cockpit.secure_agent.provider_contract import release_observation
from scripts import secure_agent_provider_demo as demo


def test_adapter_parser_only_receives_released_observation(monkeypatch):
    source = json.dumps({"step": 2, "untrusted_observation": {
        "execution_status": "succeeded", "body": "PRIVATE BODY /secret/path Authorization: fake-canary"}}).encode()
    original = bytes(source)
    calls = []
    control = object()

    class Broker:
        config = OpenAIConfig("owned-tls-fixture-model", 1024)

        def __init__(self, *args, **kwargs):
            pass

        def exchange(self, observation, request, *, control):
            calls.append((observation, request, control))
            assert observation == source
            assert request == build_request(self.config, release_observation(source))
            assert b"PRIVATE" not in request and b"fake-canary" not in request
            return b"bounded synthetic reply"

    class Planner:
        boundary_checks = {"verified": True}

        def plan(self, config, observation, exchange, *, control):
            assert observation == release_observation(source)
            assert b"PRIVATE" not in observation and b"fake-canary" not in observation
            assert exchange(build_request(config, observation), control=control) == b"bounded synthetic reply"
            return b'{"schema_version":"1","action":null,"done":true}'

    monkeypatch.setattr(provider_adapter, "OwnedProviderBroker", Broker)
    monkeypatch.setattr(provider_adapter, "LinuxOpenAIPlanner", Planner)
    provider = provider_adapter.OwnedTLSProvider(object())
    assert json.loads(provider.propose(source, control=control))["done"] is True
    assert source == original and len(calls) == 1 and calls[0][2] is control
    assert provider.boundary_checks == {"verified": True}


def test_demo_dry_run_has_no_process_audit_or_credential_lookup(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("dry run must not create runtime or audit")
    monkeypatch.setattr(demo, "OwnedTLSProvider", forbidden)
    monkeypatch.setattr(demo, "AuditSink", forbidden)
    monkeypatch.setattr(demo.tempfile, "mkdtemp", forbidden)
    audit = tmp_path / "not-created" / "audit.jsonl"
    report = demo.run_demo(audit)
    assert report["status"] == "dry_run" and report["reservations"] is None
    assert report["live_calls_enabled"] is False and report["tool_executions"] == 0
    assert not audit.parent.exists()


@pytest.mark.parametrize("options", [{"scenario": "https://elsewhere.invalid"}, {"scenario": True},
                                    {"execute": 1}, {"max_seconds": True}, {"max_seconds": 0}, {"max_seconds": 121}])
def test_demo_rejects_unbounded_configuration(options):
    with pytest.raises(ValueError, match="invalid_provider_demo_configuration"):
        demo.run_demo(**options)


def test_demo_static_failure_does_not_echo_component_error(tmp_path, monkeypatch):
    class Provider:
        def __init__(self, *args, **kwargs):
            self.broker = SimpleNamespace(broker_id="test", snapshot={}, last_receipt=None)
            self.boundary_checks = None

        def propose(self, *args, **kwargs):
            raise RuntimeError("synthetic-secret-must-not-appear")
    monkeypatch.setattr(demo, "OwnedTLSProvider", Provider)
    result = demo.run_demo(tmp_path / "audit.jsonl", execute=True)
    assert result["status"] == "failed" and result["reason"] == "provider_demo_failed"
    assert "synthetic-secret" not in json.dumps(result)


def test_demo_main_sanitizes_temporary_audit_setup_failure(monkeypatch, capsys):
    def fail(**kwargs):
        raise OSError("private-temporary-path")

    monkeypatch.setattr(demo.tempfile, "mkdtemp", fail)
    monkeypatch.setattr(demo, "OwnedTLSProvider", lambda *_a, **_k: pytest.fail("failed setup started provider"))
    assert demo.main(["--execute"]) == 2
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result["status"] == "failed" and result["reason"] == "provider_demo_failed"
    assert result["broker_id"] is None and result["reservations"] is None
    assert "private-temporary-path" not in captured.out and captured.err == ""


def test_demo_main_restores_signal_handlers_on_failure(monkeypatch, capsys):
    before = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}

    def stop(*args, **kwargs):
        assert all(signal.getsignal(number) != previous for number, previous in before.items())
        assert kwargs["execute"] is True
        return {"status": "stopped", "reason": "session_cancelled"}
    monkeypatch.setattr(demo, "run_demo", stop)
    assert demo.main(["--execute"]) == 2
    assert {number: signal.getsignal(number) for number in before} == before
    assert json.loads(capsys.readouterr().out)["reason"] == "session_cancelled"
