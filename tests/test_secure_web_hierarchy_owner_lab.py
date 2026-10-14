"""Production hierarchy identity, original owner evidence and finite lifecycle."""

import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_web_hierarchy_spec as spec
from recon_cockpit.secure_agent import network_tools_web_hierarchy_identity as identity
from recon_cockpit.secure_agent import network_tools_web_hierarchy_receipt as receipt
from recon_cockpit.secure_agent import network_tools_web_hierarchy_owner as owner
from recon_cockpit.secure_agent import network_tools_lab_contract as lab_contract
from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent.web_hierarchy_fixture import wire_response
from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab
from recon_cockpit.secure_agent.owned_lab import OwnedLab
from recon_cockpit.secure_agent.session_limits import SessionLimits
from recon_cockpit.secure_agent.isolation import IsolationUnavailable


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def raw_owner(case="nested", count=12, *, complete=True):
    ledger = []
    for path in spec.PATHS[:count]:
        request = f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n".encode("ascii")
        response = wire_response(case, path)
        ledger.append({"raw_request_base64": base64.b64encode(request).decode("ascii"),
            "response_base64": base64.b64encode(response if complete else b"").decode("ascii"),
            "method": "GET", "path": path, "status_code": int(response.split(b" ")[1]),
            "completed": complete})
    return encode({"sequence": 1, "connection_count": count, "request_count": count,
        "diagnostic": {"case": case, "ledger": ledger, "max_active_requests": min(count, 1), "errors": []}})


def lab(case=spec.CASES[0]):
    return NetworkToolsLab(case, str(uuid4()), SessionLimits(**spec.LIMITS))


@pytest.mark.parametrize("case", spec.CASES)
def test_fixed_authority_identity_commits_exact_corpus_owner_and_response_selection(case):
    value = lab(case)
    expected = identity.identity(case, value.identity["instance_id"])
    assert value.identity == expected
    assert lab_contract.validate_identity(expected, case=case) == expected
    definition = lab_contract.spec(case)
    assert definition["behavior"] == spec.case_parts(case)
    assert definition["tool_id"] == spec.TOOL_ID == fixture.tool_for_case(case)
    assert fixture.WEB_HIERARCHY_CASES == spec.CASES
    assert definition["paths"] == list(spec.PATHS) and len(definition["paths"]) == 12
    assert definition["wordlist_sha256"] == hashlib.sha256(spec.WORDLIST).hexdigest()
    assert definition["max_owner_receipt_bytes"] == 24576
    assert definition["max_connections"] == 16 and definition["max_requests"] == 12
    assert definition["max_active_requests"] == 1
    assert not value.started and value._supervisor is None
    changed = dict(expected, scenario=next(item for item in spec.CASES if item != case))
    with pytest.raises(ValueError):
        identity.validate_identity(changed)
    for path in spec.PATHS:
        expected_hash = None if case.endswith("stalled") else hashlib.sha256(wire_response(spec.case_parts(case), path)).hexdigest()
        assert definition["responses"][path] == expected_hash


@pytest.mark.parametrize("length", [1, 8193, spec.MAX_OWNER_BYTES])
def test_receipt_preserves_exact_original_bytes_including_management_sequence_and_newline(length):
    raw = b" " * length
    value = receipt.encode_owner_receipt(raw)
    assert receipt.decode_owner_receipt(value) == raw
    assert value["sha256"] == hashlib.sha256(raw).hexdigest()
    original = raw_owner()
    assert receipt.decode_owner_receipt(receipt.encode_owner_receipt(original)) == original
    assert receipt.encode_owner_receipt(original)["sha256"] != receipt.encode_owner_receipt(original[:-1])["sha256"]


@pytest.mark.parametrize("raw", [b"", b"x" * (spec.MAX_OWNER_BYTES + 1), "text", bytearray(b"x")])
def test_receipt_rejects_unbounded_or_nonbyte_input(raw):
    with pytest.raises(ValueError):
        receipt.encode_owner_receipt(raw)


@pytest.mark.parametrize("field,value", [
    ("bytes", True), ("bytes", 0), ("bytes", 2), ("bytes", spec.MAX_OWNER_BYTES + 1),
    ("sha256", "0" * 64), ("sha256", None), ("raw_base64", "eA==\n"),
    ("raw_base64", "?"), ("raw_base64", None), ("raw_base64", "eB=="), ("extra", 1),
])
def test_receipt_rejects_changed_metadata_or_noncanonical_encoding(field, value):
    item = receipt.encode_owner_receipt(b"x")
    item[field] = value
    with pytest.raises(ValueError):
        receipt.decode_owner_receipt(item)


@pytest.mark.parametrize("case", spec.CASES)
def test_owner_selection_is_closed_but_never_inferrs_fixture_success(case):
    raw = raw_owner(spec.case_parts(case))
    assert receipt.parse_owner(raw) == json.loads(raw)
    assert receipt.validate_owner_selection(raw, case) == json.loads(raw)
    assert receipt.receipt_counter_context(raw) == {"connection_count": 12, "request_count": 12}
    other = next(item for item in spec.CASES if item != case)
    with pytest.raises(ValueError, match="selection_mismatch"):
        receipt.validate_owner_selection(raw, other)


@pytest.mark.parametrize("field,value", [
    ("sequence", True), ("sequence", 2), ("connection_count", True),
    ("connection_count", -1), ("connection_count", 17), ("connection_count", 0),
    ("request_count", True), ("request_count", -1), ("request_count", 17),
    ("request_count", 11), ("diagnostic", None), ("extra", "injected"),
])
def test_envelope_rejects_invalid_sequence_or_counts(field, value):
    item = json.loads(raw_owner())
    item[field] = value
    with pytest.raises(ValueError):
        receipt.parse_owner(encode(item))


@pytest.mark.parametrize("field,value", [
    ("case", "web-hierarchy-nested"), ("case", None), ("ledger", []), ("ledger", None),
    ("max_active_requests", True), ("max_active_requests", 0), ("max_active_requests", 13),
    ("errors", ["peer string"]), ("errors", ["invalid_request", "invalid_request"]),
    ("errors", {}), ("errors", [[]]), ("extra", 1),
])
def test_ledger_envelope_rejects_unknown_or_impossible_structure(field, value):
    item = json.loads(raw_owner())
    item["diagnostic"][field] = value
    with pytest.raises(ValueError):
        receipt.parse_owner(encode(item))


@pytest.mark.parametrize("field,value", [
    ("method", "POST"), ("method", None), ("path", "x" * 1025), ("path", None),
    ("status_code", True), ("status_code", 600), ("completed", 1),
    ("raw_request_base64", ""), ("raw_request_base64", "?"),
    ("response_base64", base64.b64encode(b"x" * 1025).decode()),
    ("response_base64", ""), ("extra", 1),
])
def test_individual_request_ledger_remains_bounded_and_typed(field, value):
    item = json.loads(raw_owner())
    item["diagnostic"]["ledger"][0][field] = value
    with pytest.raises(ValueError):
        receipt.parse_owner(encode(item))


def test_incomplete_invalid_duplicate_and_concurrent_requests_remain_visible_as_evidence():
    item = json.loads(raw_owner(count=2, complete=False))
    item["diagnostic"]["ledger"][0].update(method="", path="", status_code=0)
    item["diagnostic"]["ledger"][1] = copy.deepcopy(item["diagnostic"]["ledger"][0])
    item["diagnostic"].update(errors=["invalid_request", "duplicate_path"], max_active_requests=2)
    assert receipt.parse_owner(encode(item)) == item
    assert receipt.parse_owner(raw_owner(count=0))["request_count"] == 0


@pytest.mark.parametrize("transform", [
    lambda raw: raw[:-1], lambda raw: raw + b"\n", lambda raw: raw.replace(b'"sequence":1', b'"sequence":1,"sequence":1'),
    lambda raw: raw.replace(b'"sequence":1', b'"sequence":1.0'),
    lambda raw: raw.replace(b'"sequence":1', b'"sequence":NaN'), lambda raw: b"\xff\n",
])
def test_original_management_framing_duplicate_keys_and_noninteger_numbers_are_rejected(transform):
    with pytest.raises(ValueError):
        receipt.parse_owner(transform(raw_owner()))


@pytest.mark.parametrize("case", spec.CASES)
def test_owner_accepts_production_mapping_only_and_reuses_native_service(case):
    deadline = time.monotonic() + 20
    parsed = owner.Owner().read_request(io.BytesIO(encode({"case": case, "deadline": deadline, "host_namespaces": {}})))
    assert parsed == {"case": spec.case_parts(case), "deadline": deadline, "host_namespaces": {}}
    assert owner.Owner.create_service is owner.native.Owner.create_service
    assert owner.Owner.run is owner.native.Owner.run


@pytest.mark.parametrize("change", [
    {"case": "nested"}, {"case": "web-hierarchy-unknown"}, {"target": "127.0.0.2"},
    {"deadline": True}, {"deadline": 0}, {"deadline": float("inf")}, {"deadline": time.monotonic() + 120},
])
def test_owner_rejects_arbitrary_configuration_or_unbounded_deadline(change):
    value = {"case": spec.CASES[0], "deadline": time.monotonic() + 20, "host_namespaces": {}}
    with pytest.raises(ValueError):
        owner.Owner().read_request(io.BytesIO(encode({**value, **change})))


def prepared_lab(monkeypatch, *, raw=None, change=None):
    value = lab()
    value._started = True
    stream = io.BytesIO()
    value._supervisor = SimpleNamespace(processes={"lab": SimpleNamespace(stdin=stream)})
    monkeypatch.setattr(value, "_check", lambda control: None)
    monkeypatch.setattr(value, "_verify_pins", lambda: None)
    closed = []
    monkeypatch.setattr(value, "close", lambda: closed.append(True))
    original = raw_owner() if raw is None else raw
    value._web_hierarchy_management_raw = original
    parsed = json.loads(original)
    monkeypatch.setattr(value, "_read_message", lambda: parsed if change is None else change(parsed))
    return value, stream, closed


def test_snapshot_binds_exact_original_line_and_caches_one_acknowledgement(monkeypatch):
    value, stream, closed = prepared_lab(monkeypatch)
    first = value.snapshot(object(), minimum_requests=12)
    assert receipt.decode_owner_receipt(first["web_hierarchy_owner"]) == raw_owner()
    first["web_hierarchy_owner"]["sha256"] = "0" * 64
    second = value.snapshot(object())
    assert second["web_hierarchy_owner"]["sha256"] == hashlib.sha256(raw_owner()).hexdigest()
    assert stream.getvalue() == encode({"sequence": 1, "minimum_connections": 0, "minimum_requests": 12})
    assert value._counts == {"connection_count": 12, "request_count": 12} and not closed
    with pytest.raises(IsolationUnavailable):
        value.snapshot(object(), minimum_connections=13)
    assert closed and stream.getvalue().count(b"\n") == 1


@pytest.mark.parametrize("kind", ["case", "sequence", "parsed", "missing_raw", "already_used", "not_started"])
def test_snapshot_mismatch_or_reuse_closes_before_acknowledging_counts(monkeypatch, kind):
    raw = json.loads(raw_owner())
    if kind == "case":
        raw["diagnostic"]["case"] = "empty"
    if kind == "sequence":
        raw["sequence"] = True
    value, stream, closed = prepared_lab(monkeypatch, raw=encode(raw),
        change=(lambda item: {**item, "extra": "unbound"}) if kind == "parsed" else None)
    if kind == "missing_raw":
        del value._web_hierarchy_management_raw
    if kind == "already_used":
        value._sequence = 1
    if kind == "not_started":
        value._started = False
    with pytest.raises((ValueError, IsolationUnavailable)):
        value.snapshot(object())
    assert closed and value._counts == {"connection_count": 0, "request_count": 0}
    assert stream.getvalue().count(b"\n") <= 1


@pytest.mark.parametrize("minimum", [True, -1, 17, 1.0])
@pytest.mark.parametrize("field", ["minimum_connections", "minimum_requests"])
def test_invalid_counter_barriers_never_reach_owner(monkeypatch, field, minimum):
    value, stream, closed = prepared_lab(monkeypatch)
    with pytest.raises(IsolationUnavailable):
        value.snapshot(object(), **{field: minimum})
    assert closed and not stream.getvalue()


def test_t04_message_cap_keeps_original_line_and_does_not_widen_legacy_management():
    class Capture:
        def __init__(self, raw):
            self.buffers = {"lab_out": raw}
        def wait_for(self, predicate):
            assert predicate()
    original = raw_owner()
    assert 4096 < len(original) <= receipt.MAX_MANAGEMENT_BYTES
    value = lab()
    value._supervisor = Capture(original)
    assert value._read_message() == json.loads(original)
    assert value._web_hierarchy_management_raw == original
    old = NetworkToolsLab("dig-ok", str(uuid4()), SessionLimits(**spec.LIMITS))
    old._supervisor = Capture(original)
    with pytest.raises(IsolationUnavailable):
        old._read_message()
    value._offset = 0
    value._supervisor = Capture(b"x" * receipt.MAX_MANAGEMENT_BYTES + b"\n")
    with pytest.raises(IsolationUnavailable):
        value._read_message()


def test_context_commits_receipt_hash_while_closure_retains_only_acknowledged_totals():
    ident = lab().identity
    context = {"identity": ident, "connection_count": 12, "request_count": 12,
               "web_hierarchy_owner_sha256": hashlib.sha256(raw_owner()).hexdigest()}
    assert lab_contract.validate_context(context, ident) == context
    closure = {"identity": ident, "status": "closed", "connection_count": 12, "request_count": 12}
    assert lab_contract.validate_closure(closure, ident, previous=context) == closure
    for changed in ({**closure, "request_count": 0}, {**closure, "web_hierarchy_owner_sha256": context["web_hierarchy_owner_sha256"]}):
        with pytest.raises(ValueError):
            lab_contract.validate_closure(changed, ident, previous=context)
    for changed in ({**context, "web_hierarchy_owner_sha256": "A" * 64}, {**context, "request_count": True}):
        with pytest.raises(ValueError):
            lab_contract.validate_context(changed, ident)


@pytest.mark.parametrize("attempts", range(13, 17))
def test_extra_owner_attempts_are_retained_as_negative_evidence_and_never_useful(attempts):
    from recon_cockpit.secure_agent import network_tools_contract as contract
    raw = json.loads(raw_owner())
    raw.update(connection_count=attempts, request_count=attempts)
    ledger = raw["diagnostic"]["ledger"]
    ledger.extend(copy.deepcopy(ledger[-1]) for _ in range(attempts - len(ledger)))
    raw["diagnostic"]["errors"] = ["duplicate_path"]
    envelope = receipt.encode_owner_receipt(encode(raw))
    ident = lab().identity
    context = {"identity": ident, "connection_count": attempts, "request_count": attempts,
               "web_hierarchy_owner_sha256": envelope["sha256"]}
    result = {"backend": contract.BACKEND, "owned_lab": context,
              "web_hierarchy_owner": envelope, "tool_observation": None}
    assert contract.validate_result_context(result, ident, tool_id=spec.TOOL_ID,
        execution_status="failed") == context
    assert contract.validate_result_context(result, ident, tool_id=spec.TOOL_ID,
        execution_status="succeeded") == context
    closure = {"identity": ident, "status": "closed", "connection_count": attempts, "request_count": attempts}
    assert lab_contract.validate_closure(closure, ident, previous=context) == closure
    result["tool_observation"] = {"owner_sha256": envelope["sha256"]}
    with pytest.raises(ValueError):
        contract.validate_result_context(result, ident, tool_id=spec.TOOL_ID,
            execution_status="succeeded")


def test_owner_mounts_are_readonly_and_exclusive_to_new_production_profile(monkeypatch):
    monkeypatch.setattr(OwnedLab, "_owner_command", lambda *args: ["bwrap", "--remount-ro", "/", "owner.py"])
    current = lab()._owner_command("unused", [], 7)
    legacy = NetworkToolsLab("dig-ok", str(uuid4()), SessionLimits(**spec.LIMITS))._owner_command("unused", [], 7)
    assert current[-1] == "/app/network_tools_web_hierarchy_owner.py"
    assert legacy[-1] == "/app/network_tools_lab_worker.py"
    names = ("network_tools_web_hierarchy_owner.py", "network_tools_web_hierarchy_spec.py",
             "web_hierarchy_owner.py", "web_hierarchy_spec.py", "web_hierarchy_fixture.py")
    for name in names:
        index = current.index("/app/" + name)
        assert current[index - 2] == "--ro-bind" and Path(current[index - 1]).is_file()
        assert "/app/" + name not in legacy
    assert "--cap-add" not in current


def test_standalone_owner_and_receipt_load_with_only_the_reviewed_sibling_closure(tmp_path):
    directory = Path(owner.__file__).parent
    names = ("network_tools_web_hierarchy_owner.py", "network_tools_web_hierarchy_spec.py",
             "network_tools_web_hierarchy_receipt.py", "web_hierarchy_owner.py", "web_hierarchy_spec.py",
             "web_hierarchy_fixture.py", "owned_lab_worker.py", "worker.py")
    for name in names:
        (tmp_path / name).write_bytes((directory / name).read_bytes())
    program = """import importlib.util, pathlib, sys
for filename in ('network_tools_web_hierarchy_owner.py', 'network_tools_web_hierarchy_receipt.py'):
    spec = importlib.util.spec_from_file_location('standalone_check', pathlib.Path(sys.argv[1]) / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", program, str(tmp_path)], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode()
