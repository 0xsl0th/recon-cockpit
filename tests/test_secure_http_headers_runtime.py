"""Bounded native capture and independent HTTP-header launch gates."""

import base64
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import http_headers_contract as contract
from recon_cockpit.secure_agent import http_headers_operation as operation
from recon_cockpit.secure_agent import http_headers_lab_worker, launch_admission, launcher_protocol
from recon_cockpit.secure_agent import nmap_execution, owned_lab_executor
from recon_cockpit.secure_agent.executor_worker import LaunchVerifier, digest, encode
from recon_cockpit.secure_agent.http_headers_lab import HTTPHeadersLab
from recon_cockpit.secure_agent.http_headers_lab_contract import identity
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session_limits import SessionLimits
from recon_cockpit.secure_agent.web_lab_contract import identity as web_identity
from test_secure_nmap_runtime import manifest as nmap_manifest


def policy():
    return parse_policy(json.loads(Path("examples/secure-agent-http-headers-policy.json").read_text()))


def configuration(case="vulnerable"):
    return {"version": "1", "service_id": str(uuid4()), "session_id": str(uuid4()),
            "policy": policy().to_dict(), "limits": dict(contract.LIMITS),
            "execute": True, "profile": contract.PROFILE, "case": case}


def envelope(step=2, case="vulnerable"):
    selected = parse_action(contract.action(case, step))
    host = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}
    value = {"mode": contract.PROFILE, "identity": identity(case, str(uuid4())),
        "namespaces": {name: name + ":[200]" for name in host},
        "launch": {"schema_version": "1", "mode": "nmap_http_headers_owned" if step == 1 else "http_headers_owned",
            "execute": True, "session_id": str(uuid4()), "nonce": "a" * 64,
            "sequence": 1, "action": selected.to_dict(), "action_digest": selected.digest,
            "policy": policy().to_dict(), "policy_digest": policy().digest,
            "limits": dict(contract.LIMITS), "limits_digest": digest(contract.LIMITS),
            "deadline": time.monotonic() + 30, "output_reserved_before": 0,
            "output_reserved_after": selected.parameters.max_output_bytes, "host_namespaces": host}}
    if step == 1:
        value["runtime"] = nmap_manifest()
    return value


def verify(value):
    raw = encode(value)
    consume = nmap_execution.consume_launch if "runtime" in value else owned_lab_executor.validate_launch
    return consume(raw, "a" * 64, hashlib.sha256(raw).hexdigest())


def recommit(value):
    launch = value["launch"]
    for field in ("action", "policy", "limits"):
        launch[field + "_digest"] = digest(launch[field])


@pytest.mark.parametrize("case", ("vulnerable", "corrected", "injected"))
@pytest.mark.parametrize("step", (1, 2))
def test_fixed_actions_pass_both_independent_launch_validators(case, step):
    selected = parse_action(contract.action(case, step))
    config = configuration(case)
    assert launch_admission.configuration(config) == config
    assert launch_admission.profile_allows(selected, config)
    request, _, namespaces, *_ = verify(envelope(step, case))
    assert request["tool_id"] == selected.tool_id
    assert request["parameters"] == selected.parameters.to_dict() and namespaces["net"] == "net:[200]"


@pytest.mark.parametrize("profile,case", [("fixture", None), ("discovery_fixture", None),
    ("owned_lab", "a"), ("owned_nmap_lab", "a"), ("owned_web_lab", "vulnerable")])
def test_accepted_old_profiles_never_admit_new_headers_capability(profile, case):
    selected = parse_action(contract.action("vulnerable", 2))
    assert not launch_admission.profile_allows(selected, {"profile": profile, "case": case})


def test_standalone_executor_does_not_accept_owned_headers_mode():
    raw = encode(envelope()["launch"])
    with pytest.raises(ValueError):
        LaunchVerifier("a" * 64, hashlib.sha256(raw).hexdigest()).consume(raw)


@pytest.mark.parametrize("step", (1, 2))
@pytest.mark.parametrize("fault", ("identity", "outer_profile", "inner_profile", "namespace"))
def test_fresh_commitment_cannot_relabel_an_existing_profile(step, fault):
    value = envelope(step)
    if fault == "identity": value["identity"] = web_identity("vulnerable", str(uuid4()))
    elif fault == "outer_profile": value["mode"] = "owned_web_lab"
    elif fault == "inner_profile": value["launch"]["mode"] = "nmap_web_owned" if step == 1 else "discovery_fixture"
    else: value["namespaces"] = dict(value["launch"]["host_namespaces"])
    with pytest.raises(ValueError): verify(value)


@pytest.mark.parametrize("step", (1, 2))
@pytest.mark.parametrize("field", contract.LIMITS)
def test_admission_and_executor_each_enforce_session_ceiling(step, field):
    config = configuration()
    config["limits"][field] += 1
    with pytest.raises(ValueError): launch_admission.configuration(config)
    value = envelope(step)
    value["launch"]["limits"][field] += 1
    recommit(value)
    with pytest.raises(ValueError): verify(value)


@pytest.mark.parametrize("change", [{"target": "127.0.0.2"}, {"port": 8081}, {"method": "HEAD"},
    {"timeout_seconds": 2}, {"max_output_bytes": 4096}, {"path": "/harbordesk/index.json"}])
def test_broader_policy_cannot_expand_fixed_http_runtime(change):
    value = envelope()
    launch = value["launch"]
    if "target" in change: launch["action"].update(change)
    else: launch["action"]["parameters"].update(change)
    launch["policy"].update(allowed_targets=["127.0.0.0/8"], allowed_ports=[8080, 8081], allowed_methods=["GET", "HEAD"])
    launch["output_reserved_after"] = launch["action"]["parameters"]["max_output_bytes"]
    recommit(value)
    selected = parse_action(launch["action"])
    assert parse_policy(launch["policy"]).evaluate(selected).decision == "approval_required"
    assert not launch_admission.profile_allows(selected, configuration())
    with pytest.raises(ValueError): verify(value)


def test_two_actions_exhaust_shared_output_without_reservation_replay():
    config = configuration()
    state = launch_admission.AdmissionState({"configuration": config, "deadline": 160}, clock=lambda: 100)
    def message(sequence, step, operation="admit", **extra):
        return {"version": "1", "service_id": config["service_id"], "session_id": config["session_id"],
                "sequence": sequence, "operation": operation, "action": contract.action("vulnerable", step),
                "policy_digest": digest(config["policy"]), **extra}
    first = state.handle(message(1, 1))
    assert first["reason"] is None
    assert state.handle(message(2, 1, "redeem", permit=first["permit"]))["reason"] is None
    assert state.handle(message(3, 1, "redeem", permit=first["permit"]))["reason"] == "admission_unknown_or_replayed"
    assert state.handle(message(4, 2))["reason"] is None
    denied = state.handle(message(5, 2))
    assert denied["reason"] == "admission_output_limit"
    assert denied["snapshot"] == {"executions_reserved": 2, "output_bytes_reserved": 18432}


def test_launcher_new_identity_tag_and_modules_are_explicit(monkeypatch):
    from recon_cockpit.secure_agent import launcher_isolation
    config = {**configuration(), "owned_lab": identity("vulnerable", str(uuid4()))}
    assert launcher_protocol.configuration(config) == config
    with pytest.raises(ValueError): launcher_protocol.configuration({**config, "profile": "owned_web_lab"})
    monkeypatch.setattr(launcher_isolation, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(launcher_isolation, "_namespaces", lambda: {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")})
    for profile in (contract.PROFILE, "owned_web_lab", "owned_nmap_lab", "owned_lab"):
        client = SimpleNamespace(_config={"profile": profile}, _witness_source={}, _approval_source={})
        argv = launcher_isolation.LinuxFixtureLauncher._command(client, {"stdlib": "/usr/lib/python3.13"}, [], "a" * 64)
        assert any("/http_headers_" in item for item in argv) is (profile == contract.PROFILE)
        if profile == contract.PROFILE: assert argv[-1] == "http-headers-launch-preconditions"


@pytest.mark.parametrize("fault", ["empty", "oversized", "timeout", "failed", "malformed", "success"])
def test_native_capture_is_bounded_opaque_and_never_follows_response(fault, monkeypatch):
    raw = b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.2:8080/\r\nContent-Length: 0\r\n\r\n"
    if fault == "empty": raw = b""
    elif fault == "oversized": raw = b"x" * 3000
    elif fault == "malformed": raw = b"not even HTTP"
    state = {"connections": [], "requests": []}
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *_): state["closed"] = True
        def settimeout(self, value): assert 0 < value <= 1
        def connect(self, address): state["connections"].append(address)
        def sendall(self, body): state["requests"].append(body)
        def recv(self, size):
            if state.get("received"):
                if fault == "timeout": raise TimeoutError
                if fault == "failed": raise OSError
                return b""
            state["received"] = True
            return raw[:size]
    monkeypatch.setattr(operation.socket, "socket", lambda *_: Connection())
    monkeypatch.setattr(operation.signal, "SIGALRM", 14, raising=False)
    monkeypatch.setattr(operation.signal, "ITIMER_REAL", 0, raising=False)
    monkeypatch.setattr(operation.signal, "signal", lambda *_: None)
    monkeypatch.setattr(operation.signal, "setitimer", lambda *_: None, raising=False)
    result = operation.probe("127.0.0.1", dict(contract.HTTP_PARAMETERS))
    retained = raw[:2048]
    assert result["status"] == {"empty": "failed", "oversized": "output_limit", "timeout": "timeout",
        "failed": "failed"}.get(fault, "succeeded")
    assert result["results"] == [{"target": "127.0.0.1", "port": 8080, "bytes_received": len(retained),
        "truncated": fault == "oversized", "raw_response": base64.b64encode(retained).decode(),
        "response_sha256": hashlib.sha256(retained).hexdigest()}]
    assert state["connections"] == [("127.0.0.1", 8080)] and state["closed"]
    assert state["requests"] == [b"GET /harbordesk/portal.html HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n"]


def test_lab_construction_is_inert_and_owner_request_is_bounded():
    lab = HTTPHeadersLab("injected", str(uuid4()), SessionLimits(**contract.LIMITS))
    assert lab._supervisor is None and lab._counts == {"connection_count": 0, "request_count": 0}
    request = {"case": "injected", "deadline": time.monotonic() + 30,
               "host_namespaces": {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}}
    assert http_headers_lab_worker.read_request(io.BytesIO(encode(request) + b"\n")) == request
    request["case"] = "../../external"
    with pytest.raises(ValueError): http_headers_lab_worker.read_request(io.BytesIO(encode(request) + b"\n"))
    assert lab.close()["connection_count"] == 0
