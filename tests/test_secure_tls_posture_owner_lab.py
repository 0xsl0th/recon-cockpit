"""Production TLS ownership, original-receipt limits and lifecycle boundaries."""

import hashlib
import io
import json
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_tls_posture_spec as spec
from recon_cockpit.secure_agent import network_tools_tls_posture_identity as identity
from recon_cockpit.secure_agent import network_tools_tls_posture_receipt as receipt
from recon_cockpit.secure_agent import network_tools_tls_posture_owner as owner
from recon_cockpit.secure_agent import network_tools_tls_posture_lab as lifecycle
from recon_cockpit.secure_agent import network_tools_lab_contract as lab_contract
from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab
from recon_cockpit.secure_agent.session_limits import SessionLimits
from recon_cockpit.secure_agent.isolation import IsolationUnavailable


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def raw_owner():
    return encode({"connection_count": 1, "request_count": 1,
                   "diagnostic": {"case": "modern", "expected_version": "tls1"}, "mediation": {"completed": True}})


def lab(case=spec.CASES[0]):
    return NetworkToolsLab(case, str(uuid4()), SessionLimits(**spec.LIMITS))


@pytest.mark.parametrize("case", spec.CASES)
def test_authority_identity_commits_version_case_and_mediation(case):
    value = lab(case)
    expected = identity.identity(case, value.identity["instance_id"])
    assert value.identity == expected
    assert lab_contract.validate_identity(expected, case=case) == expected
    definition = lab_contract.spec(case)
    version, variant = spec.case_parts(case)
    assert definition["tls_version"] == version and definition["behavior"] == variant
    assert definition["tool_id"] == spec.tool_for_case(case)
    assert definition["owner_private_peer"] == "unnamed_socketpair"
    assert definition["max_owner_receipt_bytes"] == 262144
    assert definition["encrypted_record_semantics_enforced"] is False
    assert not value.started and value._supervisor is None
    replacement = dict(expected, scenario=next(item for item in spec.CASES if item != case))
    with pytest.raises(ValueError):
        identity.validate_identity(replacement)


@pytest.mark.parametrize("seconds", [31, 60])
def test_new_owner_lifetime_does_not_widen_to_legacy_session(seconds):
    with pytest.raises(ValueError):
        NetworkToolsLab(spec.CASES[0], str(uuid4()),
            SessionLimits(**{**spec.LIMITS, "max_runtime_seconds": seconds}))
    assert NetworkToolsLab("dig-ok", str(uuid4()),
        SessionLimits(max_steps=1, max_runtime_seconds=60, max_output_bytes=8192))


@pytest.mark.parametrize("length", [1, 65537, spec.MAX_OWNER_BYTES])
def test_receipt_preserves_original_bytes_at_its_separate_limit(length):
    raw = b" " * length
    value = receipt.encode_owner_receipt(raw)
    assert receipt.decode_owner_receipt(value) == raw
    assert value["sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("raw", [b"", b"x" * (spec.MAX_OWNER_BYTES + 1), "not bytes", bytearray(b"x")])
def test_receipt_rejects_unbounded_or_nonbyte_input(raw):
    with pytest.raises(ValueError):
        receipt.encode_owner_receipt(raw)


@pytest.mark.parametrize("field,value", [
    ("bytes", True), ("bytes", 0), ("bytes", 2), ("bytes", spec.MAX_OWNER_BYTES + 1),
    ("sha256", "0" * 64), ("sha256", None), ("raw_base64", "eA==\n"),
    ("raw_base64", "?"), ("raw_base64", None), ("extra", 1),
])
def test_receipt_detects_metadata_and_encoding_tampering(field, value):
    item = receipt.encode_owner_receipt(b"x")
    item[field] = value
    with pytest.raises(ValueError):
        receipt.decode_owner_receipt(item)


@pytest.mark.parametrize("field,value", [
    ("connection_count", True), ("connection_count", -1), ("connection_count", 3),
    ("request_count", True), ("request_count", -1), ("request_count", 2),
    ("diagnostic", None), ("mediation", []), ("extra", "injected"),
])
def test_counter_codec_cannot_accept_false_or_out_of_range_context(field, value):
    item = json.loads(raw_owner())
    item[field] = value
    with pytest.raises(ValueError):
        receipt.receipt_counter_context(encode(item))


@pytest.mark.parametrize("raw", [
    b'{"connection_count":1,"connection_count":1,"request_count":1,"diagnostic":{},"mediation":{}}',
    b'{"connection_count":1,"request_count":1,"diagnostic":{"x":NaN},"mediation":{}}',
    b'{"connection_count":1,"request_count":1,"diagnostic":{"x":1.0},"mediation":{}}',
    b'{"connection_count":0,"request_count":1,"diagnostic":{},"mediation":{}}',
])
def test_counter_codec_rejects_duplicates_floats_constants_and_impossible_totals(raw):
    with pytest.raises(ValueError):
        receipt.receipt_counter_context(raw)


@pytest.mark.parametrize("case", spec.CASES)
def test_owner_accepts_only_closed_production_case_mapping(case):
    deadline = time.monotonic() + 20
    source = io.BytesIO(encode({"case": case, "deadline": deadline, "host_namespaces": {}}) + b"\n")
    parsed = owner.Owner().read_request(source)
    version, variant = spec.case_parts(case)
    assert parsed == {"case": variant, "version": version, "deadline": deadline, "host_namespaces": {}}


@pytest.mark.parametrize("change", [
    {"case": "modern"}, {"case": "tls-posture-tls1-hrr"}, {"version": "tls1_3"},
    {"target": "127.0.0.2"}, {"deadline": True}, {"deadline": 0}, {"deadline": float("inf")},
])
def test_owner_rejects_diagnostic_inputs_expansion_and_invalid_deadlines(change):
    value = {"case": spec.CASES[0], "deadline": time.monotonic() + 20, "host_namespaces": {}}
    with pytest.raises(ValueError):
        owner.Owner().read_request(io.BytesIO(encode({**value, **change}) + b"\n"))


def test_owner_receipt_wraps_actual_snapshot_without_changing_raw_semantics(monkeypatch):
    actual = json.loads(raw_owner())
    monkeypatch.setattr(owner.mediated.Service, "snapshot", lambda *args: actual)
    value = owner.Service.__new__(owner.Service).snapshot(0, 0, time.monotonic() + 1)
    assert json.loads(receipt.decode_owner_receipt(value["tls_posture_owner"])) == actual
    assert value["connection_count"] == value["request_count"] == 1
    assert set(value) == {"connection_count", "request_count", "tls_posture_owner"}


def prepared_lab(monkeypatch, message=None):
    value = lab()
    value._started = True
    stream = io.BytesIO()
    value._supervisor = SimpleNamespace(processes={"lab": SimpleNamespace(stdin=stream)})
    monkeypatch.setattr(value, "_check", lambda control: None)
    monkeypatch.setattr(value, "_verify_pins", lambda: None)
    closed = []
    monkeypatch.setattr(value, "close", lambda: closed.append(True))
    result = {"sequence": 1, "connection_count": 1, "request_count": 1,
              "tls_posture_owner": receipt.encode_owner_receipt(raw_owner())}
    if message is not None:
        result = message(result)
    monkeypatch.setattr(value, "_read_message", lambda: result)
    return value, stream, closed


def test_owner_snapshot_binds_original_counter_bytes_and_caches_one_receipt(monkeypatch):
    value, stream, closed = prepared_lab(monkeypatch)
    first = value.snapshot(object())
    first["tls_posture_owner"]["sha256"] = "0" * 64
    second = value.snapshot(object())
    assert second["tls_posture_owner"]["sha256"] == hashlib.sha256(raw_owner()).hexdigest()
    assert stream.getvalue().count(b"\n") == 1
    assert value._counts == {"connection_count": 1, "request_count": 1}
    assert not closed
    with pytest.raises(IsolationUnavailable):
        value.snapshot(object(), minimum_connections=2)
    assert closed


@pytest.mark.parametrize("change", [
    {"sequence": True}, {"sequence": 2}, {"connection_count": True}, {"connection_count": 2},
    {"request_count": 0}, {"tls_posture_owner": None}, {"extra": "ignored"},
])
def test_owner_snapshot_mismatch_permanently_closes_lab(monkeypatch, change):
    value, _, closed = prepared_lab(monkeypatch, lambda item: {**item, **change})
    with pytest.raises((ValueError, IsolationUnavailable)):
        value.snapshot(object())
    assert closed and value._counts == {"connection_count": 0, "request_count": 0}


@pytest.mark.parametrize("minimum", [True, -1, 3, 1.0])
def test_owner_snapshot_rejects_invalid_counter_barrier(monkeypatch, minimum):
    value, stream, closed = prepared_lab(monkeypatch)
    with pytest.raises(IsolationUnavailable):
        value.snapshot(object(), minimum_connections=minimum)
    assert not stream.getvalue() and closed


def test_owner_closure_is_separate_from_completed_peer_receipt():
    value = lab()
    ident = value.identity
    context = {"identity": ident, "connection_count": 1, "request_count": 1,
               "tls_posture_owner_sha256": hashlib.sha256(raw_owner()).hexdigest()}
    assert lab_contract.validate_context(context, ident) == context
    closure = {"identity": ident, "status": "closed", "connection_count": 1, "request_count": 1}
    assert lab_contract.validate_closure(closure, ident, previous=context) == closure
    with pytest.raises(ValueError):
        lab_contract.validate_closure({**closure, "status": "peer_closed"}, ident, previous=context)
    with pytest.raises(ValueError):
        lab_contract.validate_closure({**closure, "request_count": 0}, ident, previous=context)


def test_t02_owner_message_limit_is_separate_from_legacy_read_limit():
    class Capture:
        def __init__(self, raw):
            self.buffers = {"lab_out": raw}
        def wait_for(self, predicate):
            assert predicate()
    raw = encode({"large": "x" * 40000}) + b"\n"
    value = lab()
    value._supervisor = Capture(raw)
    assert value._read_message() == {"large": "x" * 40000}
    old = NetworkToolsLab("dig-ok", str(uuid4()), SessionLimits(**spec.LIMITS))
    old._supervisor = Capture(raw)
    with pytest.raises(IsolationUnavailable):
        old._read_message()
    value._offset = 0
    value._supervisor = Capture(b"x" * receipt.MAX_MANAGEMENT_BYTES + b"\n")
    with pytest.raises(IsolationUnavailable):
        value._read_message()


@pytest.mark.parametrize("status,code,reason,truncated,should_parse", [
    ("succeeded", 0, None, False, True), ("failed", 1, None, False, True),
    ("timeout", -9, "timeout", False, False), ("output_limit", -9, "output_limit", True, False),
])
def test_backend_keeps_process_status_while_preserving_useful_failed_observation(
        monkeypatch, status, code, reason, truncated, should_parse):
    from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
    from recon_cockpit.secure_agent import network_tools_contract as contract
    from recon_cockpit.secure_agent import network_tools_tls_posture_parser_runtime as parser
    value = AuthorizedNetworkToolsBackend.__new__(AuthorizedNetworkToolsBackend)
    value._lab_identity = lab().identity
    value._previous_context = None
    original = raw_owner()
    envelope = receipt.encode_owner_receipt(original)
    value.lab = SimpleNamespace(snapshot=lambda control: {
        "connection_count": 1, "request_count": 1, "tls_posture_owner": envelope})
    calls = []
    def parse(*args, **kwargs):
        calls.append((args, kwargs))
        return {"useful_task_completed": True}
    monkeypatch.setattr(parser, "parse_isolated_tls_posture", parse)
    monkeypatch.setattr(contract, "validate_result_context", lambda result, *args, **kwargs: result["owned_lab"])
    result = {"status": status, "truncated": truncated, "tool_observation": None,
        "raw_output_base64": "", "raw_stderr_base64": "eA==",
        "provenance": {"exit_code": code, "stop_reason": reason}}
    action = SimpleNamespace(tool_id=next(iter(spec.TOOL_VERSIONS)))
    finished = value._finish_tls_posture(result, action, SimpleNamespace(check=lambda: None), None)
    assert finished["status"] == status and finished["provenance"]["exit_code"] == code
    assert finished["tls_posture_owner"] == envelope
    assert finished["owned_lab"]["tls_posture_owner_sha256"] == envelope["sha256"]
    assert "tls_posture_owner" not in finished["owned_lab"]
    assert bool(calls) is should_parse
    if should_parse:
        assert calls[0][1]["owner_raw"] == original
        assert calls[0][1]["exit_code"] == code
        assert finished["tool_observation"]["useful_task_completed"] is True
    else:
        assert finished["tool_observation"] is None


def test_backend_rejects_mismatched_outer_receipt_before_parser(monkeypatch):
    from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
    from recon_cockpit.secure_agent import network_tools_tls_posture_parser_runtime as parser
    value = AuthorizedNetworkToolsBackend.__new__(AuthorizedNetworkToolsBackend)
    value._lab_identity = lab().identity
    value._previous_context = None
    value.lab = SimpleNamespace(snapshot=lambda control: {"connection_count": 2, "request_count": 1,
        "tls_posture_owner": receipt.encode_owner_receipt(raw_owner())})
    monkeypatch.setattr(parser, "parse_isolated_tls_posture", lambda *args, **kwargs: pytest.fail("must not parse"))
    with pytest.raises(IsolationUnavailable):
        value._finish_tls_posture({}, SimpleNamespace(tool_id=next(iter(spec.TOOL_VERSIONS))),
                                 SimpleNamespace(check=lambda: None), None)


@pytest.mark.parametrize("field,replacement", [("case", "legacy"), ("expected_version", "tls1_3")])
def test_owner_receipt_cannot_substitute_a_different_valid_fixture(monkeypatch, field, replacement):
    def substitute(message):
        raw = json.loads(raw_owner())
        raw["diagnostic"][field] = replacement
        return {**message, "tls_posture_owner": receipt.encode_owner_receipt(encode(raw))}
    value, _, closed = prepared_lab(monkeypatch, substitute)
    with pytest.raises(ValueError, match="tls_posture_owner_selection_mismatch"):
        value.snapshot(object())
    assert closed and value._counts == {"connection_count": 0, "request_count": 0}


def test_parser_projection_strips_only_reviewed_launcher_helpers():
    from recon_cockpit.secure_agent.network_tools_backend import _tls_parser_closure
    library = "/usr/lib/x86_64-linux-gnu/libc.so.6"
    closure = {"stdlib": "/usr/lib/python3.13", "files": ["/usr/bin/python3", library,
        "/usr/bin/bwrap", "/usr/bin/nsenter", "/usr/sbin/nft"], "network_tools_runtime": {}}
    assert _tls_parser_closure(closure) == {"stdlib": closure["stdlib"], "files": ["/usr/bin/python3", library]}
    assert len(closure["files"]) == 5
    assert _tls_parser_closure(None) is None
    for path in ("/usr/bin/curl", "/usr/bin/openssl", "/home/sloth/private", None):
        with pytest.raises(IsolationUnavailable):
            _tls_parser_closure({**closure, "files": [*closure["files"], path]})
