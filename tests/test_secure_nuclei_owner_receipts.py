"""Owner receipts retain actual HTTP send progress without grading scenarios."""

import base64
from copy import deepcopy
import hashlib
import io
import json
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_lab as lab_module
from recon_cockpit.secure_agent import network_tools_lab_contract as contract
from recon_cockpit.secure_agent import network_tools_lab_worker as owner
from recon_cockpit.secure_agent import network_tools_nuclei_fixture as fixture
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.session_limits import SessionLimits


def receipt(raw=b"", *, complete=False, closed=False):
    return {"version": "1", "bytes_sent": len(raw), "response_base64": base64.b64encode(raw).decode("ascii"),
        "response_sha256": hashlib.sha256(raw).hexdigest(), "send_complete": complete, "connection_closed": closed}


def context(case="nuclei-index", raw=b"", *, connections=1, requests=1, complete=False, closed=False):
    return {"identity": contract.identity(case, str(uuid4())), "connection_count": connections,
        "request_count": requests, "owner_response": receipt(raw, complete=complete, closed=closed)}


@pytest.mark.parametrize("raw", [b"", b"partial", bytes(range(256)) * 16])
def test_bounded_actual_bytes_round_trip_without_http_or_scenario_grading(raw):
    value = receipt(raw)
    assert contract.decode_owner_response(value) == raw
    with pytest.raises(ValueError):
        contract.decode_owner_response(value, require_complete=True)
    if raw:
        value.update(send_complete=True, connection_closed=True)
        assert contract.decode_owner_response(value, require_complete=True) == raw


@pytest.mark.parametrize("field,value", [("version", "2"), ("version", 1), ("bytes_sent", True),
    ("bytes_sent", -1), ("bytes_sent", 4097), ("bytes_sent", 2), ("response_base64", "***"),
    ("response_base64", "YQ==\n"), ("response_base64", "YR=="), ("response_base64", "YQ==="),
    ("response_base64", "☃"), ("response_base64", None), ("response_sha256", "a" * 64),
    ("response_sha256", hashlib.sha256(b"a").hexdigest().upper()), ("send_complete", 1),
    ("connection_closed", 1), ("send_complete", True)])
def test_receipts_reject_noncanonical_or_unproved_progress(field, value):
    candidate = receipt(b"a")
    candidate[field] = value
    with pytest.raises(ValueError, match="invalid_nuclei_owner_response"):
        contract.decode_owner_response(candidate)


@pytest.mark.parametrize("fault", ["missing", "extra", "oversized", "empty_complete", "complete_without_close"])
def test_receipt_schema_and_completion_are_closed(fault):
    value = receipt(b"a", complete=True, closed=True)
    if fault == "missing": value.pop("response_sha256")
    elif fault == "extra": value["expected_match"] = True
    elif fault == "oversized": value = receipt(b"x" * 4097)
    elif fault == "empty_complete": value = receipt(b"", complete=True, closed=True)
    else: value["connection_closed"] = False
    with pytest.raises(ValueError):
        contract.decode_owner_response(value)


@pytest.mark.parametrize("case", fixture.NUCLEI_CASES)
def test_context_accepts_actual_progress_independent_of_expected_fixture_response(case):
    value = context(case, b"arbitrary sent bytes", complete=True, closed=True)
    assert contract.validate_context(value, value["identity"]) == value
    closed = {key: item for key, item in value.items() if key != "owner_response"}
    closed["status"] = "closed"
    assert contract.validate_closure(closed, value["identity"], previous=value) == closed


@pytest.mark.parametrize("connections,requests,raw,complete,closed", [
    (0, 0, b"", False, False), (1, 0, b"", False, True), (1, 1, b"partial", False, True),
    (1, 1, b"", False, False), (1, 1, b"sent", True, True)])
def test_zero_failed_partial_and_completed_owner_contexts_are_distinct(connections, requests, raw, complete, closed):
    value = context(raw=raw, connections=connections, requests=requests, complete=complete, closed=closed)
    assert contract.validate_context(value, value["identity"]) == value


@pytest.mark.parametrize("connections,requests,raw,complete,closed", [
    (0, 0, b"", False, True), (1, 0, b"sent", False, True), (0, 1, b"", False, False),
    (2, 1, b"sent", True, True), (1, 2, b"sent", True, True), (True, 1, b"", False, False)])
def test_owner_bytes_and_close_cannot_exist_without_matching_progress(connections, requests, raw, complete, closed):
    value = context(raw=raw, connections=connections, requests=requests, complete=complete, closed=closed)
    with pytest.raises(ValueError):
        contract.validate_context(value, value["identity"])


@pytest.mark.parametrize("case", ["dig-ok", "openssl-ok", "smb-ok", "kerberos-ok", "http-options-ok"])
def test_accepted_profiles_keep_counter_only_context_and_close_receipts(case):
    identity = contract.identity(case, str(uuid4()))
    value = {"identity": identity, "connection_count": 1, "request_count": 1}
    assert contract.validate_context(value, identity) == value
    closed = {**value, "status": "closed"}
    assert contract.validate_closure(closed, identity, previous=value) == closed
    with pytest.raises(ValueError):
        contract.validate_context({**value, "owner_response": receipt()}, identity)


class Connection:
    def __init__(self, *, partial=False, invalid=False, close_gate=None):
        self.source = io.BytesIO(b"POST /public/ HTTP/1.1\r\n\r\n" if invalid else fixture.NUCLEI_REQUEST)
        self.sent = bytearray()
        self.closed = False
        self.partial = partial
        self.close_gate = close_gate

    def recv(self, count): return self.source.read(count)
    def settimeout(self, _): pass

    def send(self, raw):
        if self.partial and self.sent:
            raise BrokenPipeError("interrupted send")
        chunk = raw[:11]
        self.sent.extend(chunk)
        return len(chunk)

    def close(self):
        if self.close_gate is not None:
            assert self.close_gate.wait(2)
        self.closed = True


class Listener:
    def __init__(self, connection):
        self.connection = connection
        self.accepted = False
        self.stop = threading.Event()

    def accept(self):
        if not self.accepted:
            self.accepted = True
            return self.connection, ("127.0.0.1", 1)
        self.stop.wait(2)
        raise OSError("fixture stopped")


@pytest.mark.parametrize("case", fixture.NUCLEI_CASES[:-1])
@pytest.mark.parametrize("partial", [False, True])
def test_owner_service_receipt_contains_only_bytes_acknowledged_by_send(case, partial):
    connection = Connection(partial=partial)
    listener = Listener(connection)
    service = owner.NucleiService({"case": case, "deadline": time.monotonic() + 5}, listener)
    try:
        value = service.snapshot(1, 1, time.monotonic() + 1)
        assert value["connection_count"] == value["request_count"] == 1
        assert contract.decode_owner_response(value["owner_response"]) == bytes(connection.sent)
        assert value["owner_response"]["connection_closed"] is connection.closed is True
        assert value["owner_response"]["send_complete"] is (not partial)
        if partial:
            assert bytes(connection.sent) == fixture.response(case)[:11]
        else:
            assert bytes(connection.sent) == fixture.response(case)
    finally:
        listener.stop.set()
        service.thread.join(2)
    assert not service.thread.is_alive()


def test_snapshot_cannot_claim_complete_until_owner_connection_closes():
    close_gate = threading.Event()
    connection = Connection(close_gate=close_gate)
    listener = Listener(connection)
    service = owner.NucleiService({"case": "nuclei-index", "deadline": time.monotonic() + 5}, listener)
    try:
        pending = service.snapshot(1, 1, time.monotonic() + 1)
        assert contract.decode_owner_response(pending["owner_response"]) == fixture.response("nuclei-index")
        assert pending["owner_response"]["send_complete"] is False
        assert pending["owner_response"]["connection_closed"] is False
        with pytest.raises(ValueError):
            contract.decode_owner_response(pending["owner_response"], require_complete=True)
        close_gate.set()
        complete = service.snapshot(1, 1, time.monotonic() + 1)
        assert contract.decode_owner_response(complete["owner_response"], require_complete=True) == bytes(connection.sent)
    finally:
        close_gate.set()
        listener.stop.set()
        service.thread.join(2)


def test_invalid_request_receipt_has_no_sent_bytes_or_request_progress():
    connection = Connection(invalid=True)
    listener = Listener(connection)
    service = owner.NucleiService({"case": "nuclei-index", "deadline": time.monotonic() + 5}, listener)
    try:
        value = service.snapshot(1, 0, time.monotonic() + 1)
        assert value == {"connection_count": 1, "request_count": 0, "owner_response": receipt(closed=True)}
    finally:
        listener.stop.set()
        service.thread.join(2)


def test_stalled_owner_returns_bounded_incomplete_receipt(monkeypatch):
    stall = threading.Event()
    monkeypatch.setattr(fixture.time, "sleep", lambda _: stall.wait(2))
    connection = Connection()
    listener = Listener(connection)
    service = owner.NucleiService({"case": "nuclei-stalled", "deadline": time.monotonic() + 5}, listener)
    try:
        began = time.monotonic()
        value = service.snapshot(1, 1, time.monotonic() + 1)
        assert time.monotonic() - began < 1
        assert value == {"connection_count": 1, "request_count": 1, "owner_response": receipt()}
    finally:
        stall.set()
        listener.stop.set()
        service.thread.join(2)


@pytest.mark.parametrize("fault", ["no_request", "empty", "wrong_type", "overflow", "settled"])
def test_owner_send_callback_refuses_unbounded_or_impossible_progress(fault):
    service = owner.NucleiService.__new__(owner.NucleiService)
    service.condition = threading.Condition()
    service.requests = 0 if fault == "no_request" else 1
    service._response_settled = fault == "settled"
    service._response_bytes = bytearray(b"x" * (4096 if fault == "overflow" else 0))
    raw = b"" if fault == "empty" else "untrusted" if fault == "wrong_type" else b"x"
    previous = bytes(service._response_bytes)
    with pytest.raises(ValueError):
        service._sent(raw)
    assert bytes(service._response_bytes) == previous


def configured_lab(monkeypatch, messages, case="nuclei-index"):
    lab = lab_module.NetworkToolsLab(case, str(uuid4()), SessionLimits(max_steps=1,
        max_runtime_seconds=60, max_output_bytes=8192), execute=True)
    lab._started = True
    writes = io.BytesIO()
    lab._supervisor = SimpleNamespace(processes={"lab": SimpleNamespace(stdin=writes)}, close=lambda: None)
    monkeypatch.setattr(lab, "_check", lambda _: None)
    monkeypatch.setattr(lab, "_verify_pins", lambda: None)
    entries = iter(messages)
    monkeypatch.setattr(lab, "_read_message", lambda: next(entries))
    return lab, writes


def test_nuclei_frontend_acknowledges_receipt_without_changing_closure_counters(monkeypatch):
    response = receipt(b"sent", complete=True, closed=True)
    lab, writes = configured_lab(monkeypatch, [{"sequence": 1, "connection_count": 1,
        "request_count": 1, "owner_response": response}])
    result = lab.snapshot(object(), minimum_connections=1, minimum_requests=1)
    assert result == {"connection_count": 1, "request_count": 1, "owner_response": response}
    assert json.loads(writes.getvalue()) == {"sequence": 1, "minimum_connections": 1, "minimum_requests": 1}
    assert lab._counts == {"connection_count": 1, "request_count": 1}
    result["owner_response"]["send_complete"] = False
    assert lab._owner_response["send_complete"] is True
    closed = lab.close()
    assert set(closed) == {"identity", "status", "connection_count", "request_count"}
    assert contract.validate_closure(closed, lab.identity, previous={"identity": lab.identity,
        "connection_count": 1, "request_count": 1, "owner_response": response}) == closed


@pytest.mark.parametrize("fault", ["missing", "extra", "sequence", "bool_sequence", "count", "receipt", "counter_regression",
    "byte_regression", "closed_change", "completion_regression"])
def test_frontend_rejects_changed_or_regressing_owner_acknowledgements(monkeypatch, fault):
    first = {"sequence": 1, "connection_count": 1, "request_count": 1,
        "owner_response": receipt(b"sent", complete=True, closed=True)}
    second = deepcopy(first)
    second["sequence"] = 2
    if fault == "missing": second.pop("owner_response")
    elif fault == "extra": second["expected_match"] = True
    elif fault == "sequence": second["sequence"] = 1
    elif fault == "bool_sequence": second["sequence"] = True
    elif fault == "count": second["request_count"] = 2
    elif fault == "receipt": second["owner_response"]["response_sha256"] = "a" * 64
    elif fault == "counter_regression": second["request_count"] = 0
    elif fault == "byte_regression": second["owner_response"] = receipt(b"se", complete=True, closed=True)
    elif fault == "closed_change": second["owner_response"] = receipt(b"sentextra", complete=True, closed=True)
    else: second["owner_response"]["send_complete"] = False
    lab, _ = configured_lab(monkeypatch, [first, second])
    lab.snapshot(object())
    with pytest.raises((ValueError, IsolationUnavailable)):
        lab.snapshot(object())
    assert lab._closed


def test_existing_lab_snapshot_still_uses_original_acknowledgement_shape(monkeypatch):
    lab, _ = configured_lab(monkeypatch, [{"sequence": 1, "connection_count": 1, "request_count": 1}], "dig-ok")
    assert lab.snapshot(object()) == {"connection_count": 1, "request_count": 1}


@pytest.mark.parametrize("case,completed", [("nuclei-index", True), ("nuclei-index", False), ("dig-ok", True)])
def test_launcher_close_keeps_owner_transcript_in_previous_evidence_only(case, completed):
    from recon_cockpit.secure_agent.launcher_isolation import LinuxFixtureLauncher
    identity = contract.identity(case, str(uuid4()))
    prior = {"identity": identity, "connection_count": 1, "request_count": 1} if completed else None
    if prior is not None and case.startswith("nuclei-"):
        prior["owner_response"] = receipt(b"sent", complete=True, closed=True)
    launcher = SimpleNamespace(_stopped=threading.Event(), _lock=threading.RLock(), _closed=True,
        _cleanup_verified=True, _config={"profile": "owned_network_tools_lab"},
        _lab_receipt=None, _lab_context=prior, identity=identity)
    closed = LinuxFixtureLauncher.close(launcher)
    assert closed == {"identity": identity, "status": "closed", "connection_count": int(completed),
        "request_count": int(completed)}
    assert LinuxFixtureLauncher.close(launcher) == closed
    if case.startswith("nuclei-") and completed:
        assert "owner_response" in launcher._lab_context


@pytest.mark.parametrize("case,size,accepted", [("nuclei-index", 6000, True), ("nuclei-index", 8193, False),
    ("dig-ok", 4097, False), ("dig-ok", 4096, True)])
def test_larger_owner_message_bound_is_nuclei_only(case, size, accepted):
    lab = lab_module.NetworkToolsLab(case, str(uuid4()), SessionLimits(max_steps=1,
        max_runtime_seconds=60, max_output_bytes=8192))
    raw = b'{"raw":"' + b"x" * (size - 12) + b'"}\n'
    assert len(raw) == size - 1
    raw = b" " + raw
    lab._supervisor = SimpleNamespace(buffers={"lab_out": bytearray(raw)}, wait_for=lambda predicate: predicate())
    if accepted:
        assert len(lab._read_message()["raw"]) == size - 12
    else:
        with pytest.raises(IsolationUnavailable):
            lab._read_message()
