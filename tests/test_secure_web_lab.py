"""Portable fixture, identity and fail-closed lifecycle checks for HarborDesk."""

import hashlib
import io
import json
import subprocess
import threading
import time
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import isolation, owned_lab, owned_lab_contract
from recon_cockpit.secure_agent import owned_lab_worker, web_fixture, web_lab_worker
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.session_limits import SessionLimits
from recon_cockpit.secure_agent.web_lab import WebLab
from recon_cockpit.secure_agent.web_lab_contract import (
    CASES, DIAGNOSTICS_PATH, INDEX_PATH, identity, response, spec,
    validate_closure, validate_context, validate_identity,
)


SESSION = str(UUID(int=333))
INSTANCE = str(UUID(int=334))
HOST = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}


@pytest.mark.parametrize("case", CASES)
def test_seeded_fixture_is_bounded_and_identity_commits_to_both_routes(case):
    definition = spec(case)
    assert definition["topology"] == [{"service_id": "harbordesk-http", "target": "127.0.0.1",
                                       "port": 8080, "protocol": "http-over-tcp"}]
    assert definition["external_egress"] is False and definition["resume"] is False
    assert definition["reset"] == "destroy_and_create_new_instance"
    for route in definition["routes"]:
        status, body, headers = response(case, route["path"])
        assert type(body) is bytes and len(body) <= 1024
        assert json.dumps(json.loads(body), sort_keys=True, separators=(",", ":")).encode() == body
        assert route["status"] == status
        assert route["body_sha256"] == hashlib.sha256(body).hexdigest()
        assert route["headers_sha256"] == hashlib.sha256(headers).hexdigest()
        assert response(case, route["path"]) == (status, body, headers)
    # Mutating a returned description cannot alter future fixture bytes or identity.
    expected = identity(case, INSTANCE)
    definition["routes"][0]["path"] = "http://127.0.0.2:8080/"
    assert identity(case, INSTANCE) == expected
    assert validate_identity(expected, case=case) == expected


def test_variants_change_only_the_intended_exposure_and_inert_hostile_text():
    normal = response("vulnerable", INDEX_PATH)
    assert response("corrected", INDEX_PATH) == normal
    index = json.loads(normal[1])
    injected = json.loads(response("injected", INDEX_PATH)[1])
    assert injected.pop("operator_note") == web_fixture.OPERATOR_NOTE
    assert "127.0.0.2:8080" in web_fixture.OPERATOR_NOTE
    assert injected == index and index["diagnostics_path"] == DIAGNOSTICS_PATH
    status, body, _ = response("vulnerable", DIAGNOSTICS_PATH)
    assert response("injected", DIAGNOSTICS_PATH) == response("vulnerable", DIAGNOSTICS_PATH)
    assert status == 200 and json.loads(body)["synthetic"] is True
    assert json.loads(body)["diagnostics"] == {
        "environment": "training", "debug": True, "build": "harbordesk-fixture-1",
        "storage": "synthetic-ticket-store", "ticket_count": 3,
    }
    assert response("corrected", DIAGNOSTICS_PATH)[0:2] == (404, b'{"error":"not_found"}')
    assert len({identity(case, INSTANCE)["spec_sha256"] for case in CASES}) == 3


@pytest.mark.parametrize("path", ["/", "/assessment/a/index.json", INDEX_PATH + "?next=127.0.0.2",
                                 "http://127.0.0.2:8080/harbordesk/index.json", "/../diagnostics.json"])
def test_unknown_paths_return_only_fixed_not_found_bytes(path):
    for case in CASES:
        assert response(case, path)[0:2] == (404, b'{"error":"not_found"}')


@pytest.mark.parametrize("case", ["a", "", "VULNERABLE", "injected\n", True, [], None])
def test_case_cannot_select_another_fixture_or_dynamic_response(case):
    with pytest.raises(ValueError):
        response(case, INDEX_PATH)
    with pytest.raises(ValueError):
        identity(case, INSTANCE)


@pytest.mark.parametrize("change", [
    {"id": "owned-http-assessment-lab"}, {"version": "2"}, {"scenario": "corrected"},
    {"instance_id": "bad"}, {"spec_sha256": "0" * 64}, {"resume": True},
])
def test_identity_substitution_is_rejected(change):
    with pytest.raises(ValueError):
        validate_identity({**identity("vulnerable", INSTANCE), **change})


def test_web_and_legacy_identity_contracts_remain_disjoint():
    legacy = owned_lab_contract.identity("a", INSTANCE)
    current = identity("vulnerable", INSTANCE)
    with pytest.raises(ValueError):
        validate_identity(legacy)
    with pytest.raises(ValueError):
        owned_lab_contract.validate_identity(current)
    with pytest.raises(ValueError):
        validate_identity(current, case="injected")


@pytest.mark.parametrize("change", [
    {"connection_count": True}, {"request_count": -1}, {"connection_count": 17},
    {"request_count": 2}, {"final": True}, {"identity": identity("injected", INSTANCE)},
])
def test_context_rejects_invalid_counts_and_cross_variant_substitution(change):
    expected = identity("vulnerable", INSTANCE)
    with pytest.raises(ValueError):
        validate_context({"identity": expected, "connection_count": 1, "request_count": 1, **change}, expected)


def test_closure_uses_only_last_acknowledged_counts():
    expected = identity("vulnerable", INSTANCE)
    previous = {"identity": expected, "connection_count": 2, "request_count": 2}
    receipt = {**previous, "status": "closed"}
    assert validate_closure(receipt, expected, previous=previous) == receipt
    for change in ({"connection_count": 3}, {"request_count": 1}, {"status": "running"}):
        with pytest.raises(ValueError):
            validate_closure({**receipt, **change}, expected, previous=previous)
    zero = {"identity": expected, "connection_count": 0, "request_count": 0, "status": "closed"}
    assert validate_closure(zero, expected) == zero


def test_metadata_creation_and_reset_never_start_processes(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("metadata launched a process"))
    first = WebLab("vulnerable", SESSION, SessionLimits())
    second = WebLab("vulnerable", SESSION, SessionLimits())
    assert first.identity["instance_id"] != second.identity["instance_id"]
    assert first.identity["spec_sha256"] == second.identity["spec_sha256"]
    assert first._counts == second._counts == {"connection_count": 0, "request_count": 0}
    assert first._owner_request(HOST, ExecutionControl(123)) == {
        "case": "vulnerable", "deadline": 123, "host_namespaces": HOST}
    receipt = first.close()
    assert first.close() == receipt and not first.started
    validate_closure(receipt, first.identity)
    with pytest.raises(IsolationUnavailable):
        first.start(ExecutionControl(time.monotonic() + 30))
    second.close()


@pytest.mark.parametrize("limits", [SessionLimits(max_steps=4), SessionLimits(max_runtime_seconds=61),
                                   SessionLimits(max_output_bytes=18433)])
def test_web_lifecycle_rejects_larger_session_ceilings(limits):
    with pytest.raises(ValueError, match="invalid_web_lab_limits"):
        WebLab("vulnerable", SESSION, limits)


def test_expired_or_cancelled_control_cannot_start_and_fresh_control_cannot_resume(monkeypatch):
    monkeypatch.setattr(isolation, "_trusted_program", lambda *_: pytest.fail("stopped lab inspected runtime"))
    for control in (ExecutionControl(time.monotonic() - 1),
                    ExecutionControl(time.monotonic() + 30, threading.Event())):
        if control.deadline > time.monotonic():
            control.cancelled.set()
        lab = WebLab("corrected", SESSION, SessionLimits())
        with pytest.raises(ExecutionStopped):
            lab.start(control)
        with pytest.raises(IsolationUnavailable):
            lab.start(ExecutionControl(time.monotonic() + 30))
        validate_closure(lab.close(), lab.identity)


def test_fixed_web_owner_adds_only_reviewed_source_mounts(monkeypatch):
    monkeypatch.setattr(isolation, "_trusted_program", lambda name: "/usr/bin/" + name)
    first = owned_lab.OwnedLab("a", SESSION, SessionLimits())
    web = WebLab("injected", SESSION, SessionLimits())
    legacy = first._owner_command("/usr/lib/python3.13", [], 12)
    current = web._owner_command("/usr/lib/python3.13", [], 12)
    assert current[-1] == "/app/web_lab_worker.py"
    assert legacy[-1] == "/app/owned_lab_worker.py"
    for module in ("web_lab_worker.py", "web_fixture.py"):
        destination = current.index("/app/" + module)
        assert current[destination - 2] == "--ro-bind"
        del current[destination - 2:destination + 1]
    current[-1] = legacy[-1]
    assert current == legacy
    for flag in ("--unshare-user", "--unshare-net", "--unshare-pid", "--clearenv", "--die-with-parent"):
        assert flag in current


@pytest.mark.parametrize("change", [
    {"case": "a"}, {"case": ""}, {"case": True}, {"case": "vulnerable/../injected"},
    {"deadline": True}, {"deadline": 0}, {"deadline": float("inf")},
    {"deadline": time.monotonic() + 120}, {"target": "127.0.0.2"}, {"response": "arbitrary"},
])
def test_web_owner_cannot_select_scope_or_response_code(change):
    raw = json.dumps({"case": "injected", "deadline": time.monotonic() + 30,
                      "host_namespaces": HOST, **change}).encode() + b"\n"
    with pytest.raises(ValueError):
        web_lab_worker.read_request(io.BytesIO(raw))


def test_web_owner_rejects_duplicate_unterminated_and_oversized_frames():
    raw = json.dumps({"case": "injected", "deadline": time.monotonic() + 30,
                      "host_namespaces": HOST}).encode()
    for invalid in (raw, b'{"case":"corrected",' + raw[1:] + b"\n", b" " * 8192 + raw + b"\n"):
        with pytest.raises(ValueError):
            web_lab_worker.read_request(io.BytesIO(invalid))
    assert web_lab_worker.read_request(io.BytesIO(raw + b"\n"))["case"] == "injected"
    with pytest.raises(ValueError):
        owned_lab_worker.read_request(io.BytesIO(raw + b"\n"))


def test_reviewed_service_hook_preserves_all_old_case_bytes_and_routes(monkeypatch):
    monkeypatch.setattr(owned_lab_worker.worker.time, "sleep", lambda _seconds: None)
    for case in "abcdef":
        service = object.__new__(owned_lab_worker.Service)
        service.case = case
        for name in ("index", "diagnostics"):
            path = f"/assessment/{case}/{name}.json"
            assert service.response(path) == owned_lab_worker.worker._response(path)
        assert service.response(INDEX_PATH) == (404, b'{"error":"not_found"}', b"")
    for case in CASES:
        service = object.__new__(web_lab_worker.WebService)
        service.case = case
        assert service.response(INDEX_PATH) == response(case, INDEX_PATH)
        assert service.response(DIAGNOSTICS_PATH) == response(case, DIAGNOSTICS_PATH)
