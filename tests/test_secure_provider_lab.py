"""Portable checks of the host bootstrap's closed configuration and cleanup."""

import time

import pytest

from recon_cockpit.secure_agent import provider_lab as lab
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.provider_contract import ProviderError, build_request


REQUEST = build_request(b'{"step":1,"untrusted_observation":null}')


@pytest.mark.parametrize("scenario", [None, True, "https://example.com", "../success", ""])
def test_transport_has_no_configurable_network_or_credential_source(scenario):
    with pytest.raises(ProviderError, match="provider_invalid_transport"):
        lab.LinuxOwnedProviderTransport(scenario)


def test_constructing_transport_performs_no_process_or_filesystem_setup(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("construction must be inert")
    monkeypatch.setattr(lab.tempfile, "TemporaryDirectory", forbidden)
    monkeypatch.setattr(lab.subprocess, "Popen", forbidden)
    transport = lab.LinuxOwnedProviderTransport()
    assert transport.scenario == "success" and transport.last_receipt is None


def test_expired_control_stops_before_any_setup(monkeypatch):
    monkeypatch.setattr(lab.LinuxFixtureBackend, "check_available", lambda self: pytest.fail("setup after expiry"))
    with pytest.raises(ExecutionStopped, match="session_timeout"):
        lab.LinuxOwnedProviderTransport().exchange(REQUEST, control=ExecutionControl(time.monotonic() - 1),
                                                  context_digest="a" * 64)


@pytest.mark.parametrize("control", [object(), ExecutionControl(200, clock=lambda: 100)])
def test_transport_rejects_non_kernel_clocks_before_setup(control, monkeypatch):
    monkeypatch.setattr(lab.LinuxFixtureBackend, "check_available", lambda self: pytest.fail("invalid control reached setup"))
    with pytest.raises(ProviderError, match="provider_invalid_control"):
        lab.LinuxOwnedProviderTransport().exchange(REQUEST, control=control, context_digest="a" * 64)


def test_setup_exception_is_static_and_unknown_is_not_evidence(monkeypatch):
    def fail(self):
        raise OSError("private-canary-credential")
    monkeypatch.setattr(lab.LinuxFixtureBackend, "check_available", fail)
    transport = lab.LinuxOwnedProviderTransport()
    with pytest.raises(ProviderError, match="^provider_transport_failed$"):
        transport.exchange(REQUEST, control=ExecutionControl(time.monotonic() + 20), context_digest="b" * 64)
    receipt = transport.last_receipt
    assert receipt["boundary_checks"] is None
    assert receipt["connection_count"] is None and receipt["request_count"] is None
    assert receipt["cleanup"] == {"owner_reaped": True, "worker_reaped": True}
    assert "private-canary" not in str(receipt)
    receipt["cleanup"]["owner_reaped"] = False
    assert transport.last_receipt["cleanup"]["owner_reaped"] is True


def test_cleanup_error_is_not_hidden_by_transport_failure(tmp_path, monkeypatch):
    class Temporary:
        name = str(tmp_path)

        def cleanup(self):
            raise OSError("private-cleanup-path")

    monkeypatch.setattr(lab.LinuxFixtureBackend, "check_available", lambda self: None)
    monkeypatch.setattr(lab, "_trusted_program", lambda name: "/usr/bin/true")
    monkeypatch.setattr(lab, "_namespaces", lambda: {})
    monkeypatch.setattr(lab, "_runtime_files", lambda *args, **kwargs: ("/runtime", []))
    monkeypatch.setattr(lab.tempfile, "TemporaryDirectory", lambda **kwargs: Temporary())

    def fail(*args):
        raise OSError("private-certificate-path")
    monkeypatch.setattr(lab, "_certificates", fail)
    transport = lab.LinuxOwnedProviderTransport()
    with pytest.raises(ProviderError, match="^provider_cleanup_failed$"):
        transport.exchange(REQUEST, control=ExecutionControl(time.monotonic() + 20), context_digest="c" * 64)


def test_concurrent_transport_call_cannot_reset_active_receipt():
    transport = lab.LinuxOwnedProviderTransport()
    transport._last_receipt = {"sentinel": True}
    with transport._lock:
        with pytest.raises(ProviderError, match="provider_already_running"):
            transport.exchange(REQUEST, control=ExecutionControl(time.monotonic() + 20), context_digest="a" * 64)
    assert transport.last_receipt == {"sentinel": True}
