"""Owned fixture bytes, TLS material, lifecycle and backend authority tests."""

import base64
import hashlib
import io
import json
import ssl
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import web_tools_fixture as fixture, web_tools_tls_fixture as tls
from recon_cockpit.secure_agent import web_tools_lab_contract as lab_contract
from recon_cockpit.secure_agent import web_tools_contract as contract
from recon_cockpit.secure_agent import web_tools_lab_worker as owner
from recon_cockpit.secure_agent import web_tools_backend, web_tools_runtime, web_tools_parser_runtime
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable, LinuxFixtureBackend
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session_limits import SessionLimits
from recon_cockpit.secure_agent.web_tools_backend import AuthorizedWebToolsBackend
from recon_cockpit.secure_agent.web_tools_lab import WebToolsLab


@pytest.mark.parametrize("case", fixture.CASES)
def test_fresh_identity_pins_fixed_responses_trust_and_wordlist(case):
    first = WebToolsLab(case, str(uuid4()), SessionLimits(**contract.LIMITS))
    second = WebToolsLab(case, str(uuid4()), SessionLimits(**contract.LIMITS))
    assert first.identity != second.identity
    assert first.identity["spec_sha256"] == second.identity["spec_sha256"]
    assert first._supervisor is None and not first.started
    definition = lab_contract.spec(case)
    assert definition["external_egress"] is False and definition["resume"] is False
    for route in definition["routes"]:
        assert route["wire_sha256"] == hashlib.sha256(fixture.wire_response(case, route["path"])).hexdigest()
    if case.startswith("curl-"):
        certificate = tls.UNTRUSTED_SERVER_CERT_PEM if case == "curl-untrusted" else tls.SERVER_CERT_PEM
        assert definition["certificate_sha256"] == hashlib.sha256(certificate).hexdigest()
        assert definition["ca_sha256"] == hashlib.sha256(fixture.CA_PEM).hexdigest()
    else:
        assert definition["wordlist_sha256"] == hashlib.sha256(fixture.PATH_WORDLIST_BYTES).hexdigest()
    assert lab_contract.validate_identity(first.identity, case=case) == first.identity
    assert first.close() == first.close()
    with pytest.raises(IsolationUnavailable): first.__enter__()


@pytest.mark.parametrize("field", ("max_steps", "max_runtime_seconds", "max_output_bytes"))
def test_lab_rejects_expanded_session_ceiling(field):
    limits = dict(contract.LIMITS)
    limits[field] += 1
    with pytest.raises(ValueError): WebToolsLab("curl-ok", str(uuid4()), SessionLimits(**limits))


def test_counter_closure_uses_last_acknowledged_sample_and_rejects_changed_identity():
    expected = lab_contract.identity("ffuf-normal", str(uuid4()))
    context = {"identity": expected, "connection_count": 8, "request_count": 8}
    closure = {**context, "status": "closed"}
    assert lab_contract.validate_closure(closure, expected, previous=context) == closure
    with pytest.raises(ValueError): lab_contract.validate_closure(closure, expected)
    for changed in ({"request_count": 9}, {"connection_count": 17}, {"request_count": True},
                    {"identity": lab_contract.identity("ffuf-normal", str(uuid4()))}):
        with pytest.raises(ValueError): lab_contract.validate_context({**context, **changed}, expected)


def test_fixed_wordlist_and_no_wildcard_false_positive():
    assert fixture.WORDLIST == fixture.PATH_WORDLIST_BYTES == b"portal.html\nhealth\nrobots.txt\nadmin\napi\nbackup\nstatus\nmissing-control\n"
    assert fixture.response("ffuf-normal", fixture.HTTP_BASE + "missing-control")[0] == 404
    assert fixture.response("ffuf-wildcard", fixture.HTTP_BASE + "missing-control")[0] == 200
    assert fixture.response("ffuf-normal", fixture.HTTP_BASE + "admin")[0] == 403
    assert fixture.response("ffuf-normal", fixture.HTTP_BASE + "api")[0] == 401
    for case in fixture.CASES:
        for word in fixture.WORDS:
            _, body, _ = fixture.response(case, fixture.HTTP_BASE + word)
            assert len(body) <= fixture.MAX_BODY_BYTES


def test_injection_and_redirect_are_only_fixed_untrusted_response_data():
    for case in ("curl-injected", "ffuf-injected"):
        status, body, headers = fixture.response(case, fixture.PORTAL_PATH)
        assert status == 200 and fixture.HOSTILE_NOTE.encode() in body + headers
    assert fixture.HOSTILE_NOTE.encode() not in fixture.wire_response("curl-ok", fixture.PORTAL_PATH)
    wire = fixture.wire_response("curl-redirect", fixture.PORTAL_PATH)
    assert wire.startswith(b"HTTP/1.1 302 ") and b"Location: https://127.0.0.2:8080/" in wire
    assert fixture.wire_response("curl-malformed", fixture.PORTAL_PATH).count(b"Content-Length:") == 2


@pytest.mark.parametrize("fault", ("case", "deadline", "extra", "duplicate", "oversized"))
def test_owner_bootstrap_refuses_unreviewed_configuration(fault):
    request = {"case": "curl-ok", "deadline": time.monotonic() + 20, "host_namespaces": {}}
    assert owner.read_request(io.BytesIO(json.dumps(request).encode() + b"\n")) == request
    if fault == "case": request["case"] = "../host"
    if fault == "deadline": request["deadline"] += 60
    if fault == "extra": request["url"] = "https://example.invalid/"
    raw = json.dumps(request).encode() + b"\n"
    if fault == "duplicate": raw = raw[:-2] + b',"case":"curl-ok"}\n'
    if fault == "oversized": raw = b"x" * 8193 + b"\n"
    with pytest.raises(ValueError): owner.read_request(io.BytesIO(raw))


def _handshake(client_context, server_context, hostname):
    client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(client_in, client_out, server_hostname=hostname)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    done = set()
    for _ in range(100):
        for name, peer in (("client", client), ("server", server)):
            if name not in done:
                try:
                    peer.do_handshake()
                    done.add(name)
                except ssl.SSLWantReadError:
                    pass
        for outbound, inbound in ((client_out, server_in), (server_out, client_in)):
            data = outbound.read()
            if data: inbound.write(data)
        if len(done) == 2: return client
    raise AssertionError("bounded in-memory TLS handshake did not complete")


@pytest.mark.parametrize("case,hostname,accepted", [("curl-ok", fixture.TLS_NAME, True),
    ("curl-untrusted", fixture.TLS_NAME, False), ("curl-ok", "wrong.test", False)])
def test_public_fixture_certificates_verify_trust_and_hostname_without_network(tmp_path, case, hostname, accepted):
    cert = tmp_path / "public-test-cert.pem"
    key = tmp_path / "public-test-key.pem"
    cert.write_bytes(tls.UNTRUSTED_SERVER_CERT_PEM if case == "curl-untrusted" else tls.SERVER_CERT_PEM)
    key.write_bytes(tls.SERVER_KEY_PEM)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, key)
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.load_verify_locations(cadata=fixture.CA_PEM.decode("ascii"))
    if accepted:
        connection = _handshake(client, server, hostname)
        assert connection.getpeercert()["subjectAltName"] == (("DNS", fixture.TLS_NAME),)
        assert connection.getpeercert()["notBefore"] == "Jan  1 00:00:00 2020 GMT"
        assert connection.getpeercert()["notAfter"] == "Jan  1 00:00:00 2100 GMT"
    else:
        with pytest.raises(ssl.SSLCertVerificationError): _handshake(client, server, hostname)


def _backend(monkeypatch, case, *, requests=None, status="succeeded", parsed=True):
    policy = parse_policy({"schema_version": "1", "policy_version": "web-tools-test",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": list(contract.PARAMETERS),
        "allowed_ports": [8080], "allowed_methods": ["GET"], "max_timeout_seconds": 10,
        "max_output_bytes": 8192, "max_targets": 1, "require_approval": False,
        "approval_ttl_seconds": 60})
    session = str(uuid4())
    lab = WebToolsLab(case, session, SessionLimits(**contract.LIMITS))
    backend = AuthorizedWebToolsBackend(policy, session, lab.limits, lab, execute=True)
    action = parse_action(contract.action(case))
    manifest = {"tool_id": action.tool_id}
    backend._web_tools_manifest = manifest
    calls = []
    host_namespaces = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}
    lab._lab_namespaces = {name: name + ":[200]" for name in host_namespaces}
    monkeypatch.setattr(web_tools_backend, "_namespaces", lambda: dict(host_namespaces))
    monkeypatch.setattr(LinuxFixtureBackend, "check_available", lambda *_: None)
    monkeypatch.setattr(lab, "_check_available", lambda: None)
    monkeypatch.setattr(lab, "start", lambda control: calls.append(("start", control)))
    def snapshot(control, **bounds):
        calls.append(("snapshot", bounds))
        number = (8 if case.startswith("ffuf-") else 1) if requests is None else requests
        return {"connection_count": max(1, number), "request_count": number}
    monkeypatch.setattr(lab, "snapshot", snapshot)
    def runtime(**kwargs):
        calls.append(("runtime", kwargs))
        return {"status": status, "truncated": False, "raw_output_base64": base64.b64encode(b"raw").decode()}
    monkeypatch.setattr(web_tools_runtime, "run_web_tool_owned", runtime)
    monkeypatch.setattr(web_tools_runtime, "validate_manifest", lambda value, **_: value)
    def parser(*args, **kwargs):
        calls.append(("parser", kwargs))
        if not parsed: raise ValueError("invalid_output")
        return {"parsed": True}
    monkeypatch.setattr(web_tools_parser_runtime, "parse_isolated_tool_output", parser)
    return backend, action, policy, ExecutionControl(time.monotonic() + 30), calls


@pytest.mark.parametrize("case,minimum", [("curl-ok", 1), ("ffuf-normal", 8), ("ffuf-wildcard", 8)])
def test_backend_binds_pin_authority_and_completed_request_count(monkeypatch, case, minimum):
    backend, action, policy, control, calls = _backend(monkeypatch, case)
    result = backend.run(action, policy, control=control)
    assert result["owned_lab"]["request_count"] == minimum
    launched = next(value for kind, value in calls if kind == "runtime")
    assert launched["manifest"] is backend._web_tools_manifest
    assert launched["control"] is control
    assert launched["launch"]["launch"]["host_namespaces"] == {
        name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}
    assert launched["launch"]["namespaces"] == backend.lab._lab_namespaces
    assert all(launched["launch"]["namespaces"][name] != identity
               for name, identity in launched["launch"]["launch"]["host_namespaces"].items())
    assert launched["launch"]["launch"]["action_digest"] == action.digest
    assert launched["launch"]["launch"]["output_reserved_after"] == 8192
    assert next(value for kind, value in calls if kind == "snapshot") == {"minimum_connections": minimum, "minimum_requests": minimum}
    assert dict(backend.snapshot) == {"executions_reserved": 1, "output_bytes_reserved": 8192}
    with pytest.raises(IsolationUnavailable): backend.run(action, policy, control=control)
    assert len([1 for kind, _ in calls if kind == "runtime"]) == 1


def test_ffuf_exit_zero_without_complete_output_never_waits_for_invented_requests(monkeypatch):
    backend, action, policy, control, calls = _backend(monkeypatch, "ffuf-stalled", requests=1, parsed=False)
    result = backend.run(action, policy, control=control)
    assert result["tool_observation"] is None
    assert next(value for kind, value in calls if kind == "snapshot") == {"minimum_connections": 0, "minimum_requests": 0}


def test_failed_tls_records_no_http_and_never_parses_failure_output(monkeypatch):
    backend, action, policy, control, calls = _backend(monkeypatch, "curl-untrusted", requests=0, status="failed")
    result = backend.run(action, policy, control=control)
    assert result["owned_lab"]["request_count"] == 0
    assert not any(kind == "parser" for kind, _ in calls)


@pytest.mark.parametrize("case,requests", [("curl-ok", 2), ("ffuf-normal", 9), ("curl-untrusted", 1)])
def test_backend_closes_on_unexpected_http_work(monkeypatch, case, requests):
    backend, action, policy, control, calls = _backend(monkeypatch, case, requests=requests,
        status="failed" if case == "curl-untrusted" else "succeeded")
    with pytest.raises(IsolationUnavailable): backend.run(action, policy, control=control)
    assert backend.lab._closed


def test_parser_isolation_failure_closes_lab_and_does_not_return_normalized_result(monkeypatch):
    backend, action, policy, control, _ = _backend(monkeypatch, "curl-ok")
    def unavailable(*args, **kwargs): raise IsolationUnavailable("unavailable")
    monkeypatch.setattr(web_tools_parser_runtime, "parse_isolated_tool_output", unavailable)
    with pytest.raises(IsolationUnavailable): backend.run(action, policy, control=control)
    assert backend.lab._closed and backend.snapshot["executions_reserved"] == 1


@pytest.mark.parametrize("fault", ("scope", "other_tool", "cancelled", "changed_policy", "changed_lab"))
def test_backend_rejects_changed_authority_before_any_runtime(monkeypatch, fault):
    backend, action, policy, control, calls = _backend(monkeypatch, "curl-ok")
    if fault == "scope": action = parse_action({**action.to_dict(), "target": "127.0.0.2"})
    if fault == "other_tool": action = parse_action(contract.action("ffuf-normal"))
    if fault == "cancelled": control = ExecutionControl(time.monotonic() - 1)
    if fault == "changed_policy": policy = parse_policy({**policy.to_dict(), "policy_version": "changed"})
    if fault == "changed_lab": backend.lab._identity = lab_contract.identity("curl-ok", str(uuid4()))
    with pytest.raises((IsolationUnavailable, ExecutionStopped)): backend.run(action, policy, control=control)
    assert not calls and backend.lab._closed and backend.snapshot["executions_reserved"] == 0
