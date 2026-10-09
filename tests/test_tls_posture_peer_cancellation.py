"""Peer cancellation and deadline checks independent of cross-thread close."""

import socket
import threading
import time

import pytest

from recon_cockpit.secure_agent import tls_posture_diagnostic_fixture as fixture


def test_cancel_after_partial_write_does_not_claim_complete_record():
    stop = threading.Event()
    class PartialConnection:
        def settimeout(self, seconds):
            assert 0 < seconds <= 0.05
        def send(self, raw):
            stop.set()
            return 2
    ledger = fixture.new_ledger("hrr", "tls1_3")
    stream = fixture.RecordIO(PartialConnection(), time.monotonic() + 2, ledger, cancel_event=stop)
    with pytest.raises(ValueError, match="tls_posture_owner_cancelled"):
        stream.send(b"\x15\3\3\0\2\2\x46")
    assert ledger["sent_bytes"] == 0
    assert ledger["completed"] is False


@pytest.mark.parametrize("operation", ["receive", "send"])
def test_polling_still_honors_original_absolute_deadline(monkeypatch, operation):
    stop = threading.Event()
    calls = []
    def bounded(deadline):
        calls.append(deadline)
        if len(calls) > 2:
            raise ValueError("tls_posture_owner_deadline")
        return 0.02
    class StalledConnection:
        def settimeout(self, seconds):
            assert seconds == 0.02
        def recv(self, size):
            raise socket.timeout()
        def send(self, raw):
            raise socket.timeout()
    monkeypatch.setattr(fixture, "remaining", bounded)
    ledger = fixture.new_ledger("hrr", "tls1_3")
    stream = fixture.RecordIO(StalledConnection(), 42, ledger, cancel_event=stop)
    with pytest.raises(ValueError, match="tls_posture_owner_deadline"):
        if operation == "send":
            stream.send(b"\x15\3\3\0\2\2\x46")
        else:
            stream.receive()
    assert calls == [42, 42, 42]
    assert ledger["received_bytes"] == ledger["sent_bytes"] == 0


def test_diagnostic_default_keeps_original_timeout_behavior():
    class StalledConnection:
        def settimeout(self, seconds):
            assert 0 < seconds <= 1
        def recv(self, size):
            raise socket.timeout()
    stream = fixture.RecordIO(StalledConnection(), time.monotonic() + 2,
                              fixture.new_ledger("hrr", "tls1_3"))
    with pytest.raises(socket.timeout):
        stream.receive()
