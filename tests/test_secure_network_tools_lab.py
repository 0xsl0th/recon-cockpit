"""Owned fixture bytes, TLS material, lifecycle and backend authority tests."""

import base64
import hashlib
import io
import json
import ssl
import struct
import threading
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as fixture, web_tools_tls_fixture as tls
from recon_cockpit.secure_agent import network_tools_lab_contract as lab_contract
from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_lab_worker as owner
from recon_cockpit.secure_agent import network_tools_ssh_fixture as ssh_fixture
from recon_cockpit.secure_agent import network_tools_backend, network_tools_runtime, network_tools_parser_runtime
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable, LinuxFixtureBackend
from recon_cockpit.secure_agent.models import parse_action, parse_policy
from recon_cockpit.secure_agent.session_limits import SessionLimits
from recon_cockpit.secure_agent.network_tools_backend import AuthorizedNetworkToolsBackend
from recon_cockpit.secure_agent.network_tools_lab import NetworkToolsLab


@pytest.mark.parametrize("case", fixture.CASES)
def test_fresh_identity_pins_fixed_protocol_bytes_and_tls_material(case):
    first = NetworkToolsLab(case, str(uuid4()), SessionLimits(**contract.LIMITS))
    second = NetworkToolsLab(case, str(uuid4()), SessionLimits(**contract.LIMITS))
    assert first.identity != second.identity
    assert first.identity["spec_sha256"] == second.identity["spec_sha256"]
    assert not first.started and first._supervisor is None
    definition = lab_contract.spec(case)
    assert definition["external_egress"] is False and definition["resume"] is False
    if case.startswith("dig-"):
        assert definition["response_sha256"] == hashlib.sha256(fixture.dns_response(case, fixture.dns_query())).hexdigest()
        assert definition["request_count_means"] == "validated_dns_questions"
    elif case.startswith("openssl-"):
        certificate = tls.UNTRUSTED_SERVER_CERT_PEM if case == "openssl-untrusted" else tls.SERVER_CERT_PEM
        assert definition["certificate_sha256"] == hashlib.sha256(certificate).hexdigest()
        assert definition["ca_sha256"] == hashlib.sha256(fixture.CA_PEM).hexdigest()
        assert definition["request_count_means"] == "server_completed_tls_handshakes"
        assert definition["application_payloads"] == "none"
    elif case.startswith("ssh-"):
        assert definition["ssh"]["public_key_sha256"] == hashlib.sha256(fixture.SSH_PUBLIC_BLOB).hexdigest()
        assert definition["request_count_means"] == "ssh_host_key_replies_sent"
    elif case.startswith("ldap-"):
        assert definition["ldap"]["base_dn"] == "" and definition["ldap"]["scope"] == "base"
        assert definition["request_count_means"] == "validated_rootdse_searches"
    else:
        assert definition["smb"]["dialect"] == "SMB2_02"
        assert definition["smb"]["filesystem"] is False and definition["smb"]["credentials"] is False
        assert definition["smb"]["shares"] == fixture.smb_shares(case)
        assert definition["request_count_means"] == "validated_level1_share_enumerations"
    assert lab_contract.validate_identity(first.identity, case=case) == first.identity
    assert first.close() == first.close()
    with pytest.raises(IsolationUnavailable): first.__enter__()


@pytest.mark.parametrize("field", ("max_steps", "max_runtime_seconds", "max_output_bytes"))
def test_lab_rejects_expanded_session_ceiling(field):
    limits = dict(contract.LIMITS)
    limits[field] += 1
    with pytest.raises(ValueError): NetworkToolsLab("openssl-ok", str(uuid4()), SessionLimits(**limits))


def test_counter_closure_uses_last_acknowledged_sample_and_rejects_changed_identity():
    expected = lab_contract.identity("dig-ok", str(uuid4()))
    context = {"identity": expected, "connection_count": 1, "request_count": 1}
    closure = {**context, "status": "closed"}
    assert lab_contract.validate_closure(closure, expected, previous=context) == closure
    with pytest.raises(ValueError): lab_contract.validate_closure(closure, expected)
    for changed in ({"request_count": 9}, {"connection_count": 17}, {"request_count": True},
                    {"identity": lab_contract.identity("dig-ok", str(uuid4()))}):
        with pytest.raises(ValueError): lab_contract.validate_context({**context, **changed}, expected)


@pytest.mark.parametrize("case", [c for c in fixture.CASES if c.startswith("dig-")])
def test_dns_is_fixed_and_preserves_only_validated_transaction_id(case):
    query = fixture.dns_query(b"\x12\x34")
    response = fixture.dns_response(case, query)
    assert response[:2] == b"\x12\x34"
    assert len(response) <= fixture.MAX_DNS_BYTES
    assert (fixture.HOSTILE_NOTE.encode() in response) is (case == "dig-injected")
    assert response[2:4] == (b"\x84\x03" if case == "dig-nxdomain" else b"\x84\x00")
    assert response[6:8] == (b"\x00\x00" if case == "dig-nxdomain" else b"\x00\x01")
    for invalid in (b"", query[:-1], query + b"extra", query[:2] + b"\x01" + query[3:],
                    query.replace(b"harbordesk", b"outside123"), query[:-4] + b"\x00\x1c\x00\x01"):
        with pytest.raises(ValueError): fixture.dns_response(case, invalid)


def test_dns_tcp_framing_is_bounded_and_handles_partial_reads():
    import struct
    query = fixture.dns_query()
    class Connection:
        def __init__(self, raw): self.stream = io.BytesIO(raw)
        def recv(self, count): return self.stream.read(min(count, 3))
    assert owner.read_dns_query(Connection(struct.pack("!H", len(query)) + query)) == query
    for invalid in (b"", b"\x02\x01", b"\x00\x01x", struct.pack("!H", len(query)) + query[:-1]):
        with pytest.raises(ValueError): owner.read_dns_query(Connection(invalid))


@pytest.mark.parametrize("fault", ("case", "deadline", "extra", "duplicate", "oversized"))
def test_owner_bootstrap_refuses_unreviewed_configuration(fault):
    request = {"case": "openssl-ok", "deadline": time.monotonic() + 20, "host_namespaces": {}}
    assert owner.read_request(io.BytesIO(json.dumps(request).encode() + b"\n")) == request
    if fault == "case": request["case"] = "../host"
    if fault == "deadline": request["deadline"] += 60
    if fault == "extra": request["url"] = "https://example.invalid/"
    raw = json.dumps(request).encode() + b"\n"
    if fault == "duplicate": raw = raw[:-2] + b',"case":"openssl-ok"}\n'
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


@pytest.mark.parametrize("case,hostname,accepted", [("openssl-ok", fixture.TLS_NAME, True),
    ("openssl-untrusted", fixture.TLS_NAME, False), ("openssl-ok", "wrong.test", False)])
def test_public_fixture_certificates_verify_trust_and_hostname_without_network(tmp_path, case, hostname, accepted):
    cert = tmp_path / "public-test-cert.pem"
    key = tmp_path / "public-test-key.pem"
    cert.write_bytes(tls.UNTRUSTED_SERVER_CERT_PEM if case == "openssl-untrusted" else tls.SERVER_CERT_PEM)
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
    policy = parse_policy({"schema_version": "1", "policy_version": "network-tools-test",
        "allowed_targets": ["127.0.0.1/32"], "allowed_tools": list(contract.PARAMETERS),
        "allowed_ports": [8080], "allowed_methods": ["GET"], "max_timeout_seconds": 5,
        "max_output_bytes": 8192, "max_targets": 1, "require_approval": False,
        "approval_ttl_seconds": 60})
    session = str(uuid4())
    lab = NetworkToolsLab(case, session, SessionLimits(**contract.LIMITS))
    backend = AuthorizedNetworkToolsBackend(policy, session, lab.limits, lab, execute=True)
    action = parse_action(contract.action(case))
    manifest = {"tool_id": action.tool_id}
    backend._network_tools_manifest = manifest
    calls = []
    host_namespaces = {name: name + ":[100]" for name in ("user", "net", "mnt", "pid")}
    lab._lab_namespaces = {name: name + ":[200]" for name in host_namespaces}
    monkeypatch.setattr(network_tools_backend, "_namespaces", lambda: dict(host_namespaces))
    monkeypatch.setattr(LinuxFixtureBackend, "check_available", lambda *_: None)
    monkeypatch.setattr(lab, "_check_available", lambda: None)
    monkeypatch.setattr(lab, "start", lambda control: calls.append(("start", control)))
    def snapshot(control, **bounds):
        calls.append(("snapshot", bounds))
        number = 1 if requests is None else requests
        return {"connection_count": max(1, number), "request_count": number}
    monkeypatch.setattr(lab, "snapshot", snapshot)
    def runtime(**kwargs):
        calls.append(("runtime", kwargs))
        return {"status": status, "truncated": False, "raw_output_base64": base64.b64encode(b"raw").decode(), "raw_stderr_base64": ""}
    monkeypatch.setattr(network_tools_runtime, "run_network_tool_owned", runtime)
    monkeypatch.setattr(network_tools_runtime, "validate_manifest", lambda value, **_: value)
    def parser(*args, **kwargs):
        calls.append(("parser", kwargs))
        if not parsed: raise ValueError("invalid_output")
        return {"parsed": True}
    monkeypatch.setattr(network_tools_parser_runtime, "parse_isolated_tool_output", parser)
    return backend, action, policy, ExecutionControl(time.monotonic() + 30), calls


@pytest.mark.parametrize("case,minimum", [("openssl-ok", 1), ("dig-ok", 1), ("dig-nxdomain", 1)])
def test_backend_binds_pin_authority_and_completed_request_count(monkeypatch, case, minimum):
    backend, action, policy, control, calls = _backend(monkeypatch, case)
    result = backend.run(action, policy, control=control)
    assert result["owned_lab"]["request_count"] == minimum
    launched = next(value for kind, value in calls if kind == "runtime")
    assert launched["manifest"] is backend._network_tools_manifest
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


def test_exit_zero_without_valid_output_never_waits_for_invented_protocol_progress(monkeypatch):
    backend, action, policy, control, calls = _backend(monkeypatch, "dig-stalled", requests=1, parsed=False)
    result = backend.run(action, policy, control=control)
    assert result["tool_observation"] is None
    assert next(value for kind, value in calls if kind == "snapshot") == {"minimum_connections": 0, "minimum_requests": 0}


def test_failed_tls_records_no_handshake_and_never_parses_failure_output(monkeypatch):
    backend, action, policy, control, calls = _backend(monkeypatch, "openssl-untrusted", requests=0, status="failed")
    result = backend.run(action, policy, control=control)
    assert result["owned_lab"]["request_count"] == 0
    assert not any(kind == "parser" for kind, _ in calls)


@pytest.mark.parametrize("case,requests", [("openssl-ok", 2), ("dig-ok", 9), ("openssl-untrusted", 1)])
def test_backend_closes_on_unexpected_protocol_work(monkeypatch, case, requests):
    backend, action, policy, control, calls = _backend(monkeypatch, case, requests=requests,
        status="failed" if case == "openssl-untrusted" else "succeeded")
    with pytest.raises((IsolationUnavailable, ValueError)): backend.run(action, policy, control=control)
    assert backend.lab._closed


def test_parser_isolation_failure_closes_lab_and_does_not_return_normalized_result(monkeypatch):
    backend, action, policy, control, _ = _backend(monkeypatch, "openssl-ok")
    def unavailable(*args, **kwargs): raise IsolationUnavailable("unavailable")
    monkeypatch.setattr(network_tools_parser_runtime, "parse_isolated_tool_output", unavailable)
    with pytest.raises((IsolationUnavailable, ValueError)): backend.run(action, policy, control=control)
    assert backend.lab._closed and backend.snapshot["executions_reserved"] == 1


@pytest.mark.parametrize("fault", ("scope", "other_tool", "cancelled", "changed_policy", "changed_lab"))
def test_backend_rejects_changed_authority_before_any_runtime(monkeypatch, fault):
    backend, action, policy, control, calls = _backend(monkeypatch, "openssl-ok")
    if fault == "scope": action = parse_action({**action.to_dict(), "target": "127.0.0.2"})
    if fault == "other_tool": action = parse_action(contract.action("dig-ok"))
    if fault == "cancelled": control = ExecutionControl(time.monotonic() - 1)
    if fault == "changed_policy": policy = parse_policy({**policy.to_dict(), "policy_version": "changed"})
    if fault == "changed_lab": backend.lab._identity = lab_contract.identity("openssl-ok", str(uuid4()))
    with pytest.raises((IsolationUnavailable, ExecutionStopped)): backend.run(action, policy, control=control)
    assert not calls and backend.lab._closed and backend.snapshot["executions_reserved"] == 0


def test_public_ssh_signature_matches_independently_authored_crypto_vector():
    # The committed vector was produced and verified with cryptography's
    # RSA/PKCS1v15/SHA256 implementation, not this fixture's math.
    assert ssh_fixture.sign_sha256(ssh_fixture.SIGNATURE_VECTOR_MESSAGE) == ssh_fixture.SIGNATURE_VECTOR
    assert ssh_fixture.sign_sha256(ssh_fixture.SIGNATURE_VECTOR_MESSAGE + b"changed") != ssh_fixture.SIGNATURE_VECTOR
    assert ssh_fixture.RSA_N.bit_length() == 2048 and ssh_fixture.RSA_E == 65537
    assert ssh_fixture.public_blob() == fixture.SSH_PUBLIC_BLOB
    assert fixture.SSH_FINGERPRINT == "SHA256:" + base64.b64encode(hashlib.sha256(fixture.SSH_PUBLIC_BLOB).digest()).decode().rstrip("=")


@pytest.mark.parametrize("value", [0, 1, ssh_fixture.GROUP14_P - 1, ssh_fixture.GROUP14_P])
def test_ssh_rejects_invalid_peer_dh_values(value):
    with pytest.raises(ValueError):
        ssh_fixture._client_dh(b"\x1e" + ssh_fixture.mpint(value))


class _MemoryConnection:
    def __init__(self, raw):
        self.source, self.sent = io.BytesIO(raw), bytearray()
    def recv(self, size):
        return self.source.read(min(size, 3))
    def sendall(self, raw):
        self.sent.extend(raw)
    def settimeout(self, value):
        assert 0 < value <= 2


def test_genuine_ssh_exchange_has_verifiable_hash_signature_and_no_login(monkeypatch):
    client_banner = b"SSH-2.0-Public_test_client"
    client_init = b"\x14" + b"C" * 16 + b"".join(ssh_fixture.ssh_string(v) for v in ssh_fixture.KEX_NAMES) + b"\x00" * 5
    private = 123456789
    client_dh = pow(2, private, ssh_fixture.GROUP14_P)
    wire = client_banner + b"\r\n" + ssh_fixture._packet(client_init) + ssh_fixture._packet(b"\x1e" + ssh_fixture.mpint(client_dh))
    connection = _MemoryConnection(wire)
    assert ssh_fixture.serve(connection, banner=fixture.SSH_BANNER, deadline=time.monotonic() + 10)
    outgoing = _MemoryConnection(bytes(connection.sent))
    assert ssh_fixture._read_banner(outgoing, time.monotonic() + 2) == fixture.SSH_BANNER
    server_init = ssh_fixture._read_packet(outgoing, time.monotonic() + 2)
    reply = ssh_fixture._read_packet(outgoing, time.monotonic() + 2)
    assert reply[0] == 31
    blob, offset = ssh_fixture._take_string(reply, 1)
    dh, offset = ssh_fixture._take_string(reply, offset)
    signature, offset = ssh_fixture._take_string(reply, offset)
    assert offset == len(reply) and blob == fixture.SSH_PUBLIC_BLOB
    algorithm, cursor = ssh_fixture._take_string(signature, 0)
    value, cursor = ssh_fixture._take_string(signature, cursor)
    assert algorithm == b"rsa-sha2-256" and cursor == len(signature)
    server_dh = int.from_bytes(dh, "big")
    shared = pow(server_dh, private, ssh_fixture.GROUP14_P)
    exchange = b"".join(ssh_fixture.ssh_string(v) for v in (client_banner, fixture.SSH_BANNER,
        client_init, server_init, blob)) + ssh_fixture.mpint(client_dh) + ssh_fixture.mpint(server_dh) + ssh_fixture.mpint(shared)
    signed_digest = hashlib.sha256(hashlib.sha256(exchange).digest()).digest()
    decoded = pow(int.from_bytes(value, "big"), ssh_fixture.RSA_E, ssh_fixture.RSA_N).to_bytes(256, "big")
    assert decoded == b"\x00\x01" + b"\xff" * 202 + b"\x00" + bytes.fromhex("3031300d060960864801650304020105000420") + signed_digest
    assert not outgoing.source.read()  # No encrypted session, NEWKEYS or userauth.


@pytest.mark.parametrize("fault", ["oversized", "negative_mpint", "redundant_mpint", "banner", "algorithm", "optimistic_kex"])
def test_ssh_input_bounds_and_negotiation_fail_closed(fault):
    with pytest.raises(ValueError):
        if fault == "oversized":
            ssh_fixture._read_packet(_MemoryConnection(struct.pack("!I", 8193)), time.monotonic() + 2)
        elif fault in {"negative_mpint", "redundant_mpint"}:
            raw = b"\x80" if fault == "negative_mpint" else b"\x00\x01"
            ssh_fixture._client_dh(b"\x1e" + ssh_fixture.ssh_string(raw))
        elif fault == "banner":
            ssh_fixture._read_banner(_MemoryConnection(b"SSH-2.0-" + b"x" * 256), time.monotonic() + 2)
        else:
            names = list(ssh_fixture.KEX_NAMES)
            if fault == "algorithm": names[0] = b"diffie-hellman-group1-sha1"
            payload = b"\x14" + b"x" * 16 + b"".join(ssh_fixture.ssh_string(v) for v in names) + (b"\x01" if fault == "optimistic_kex" else b"\x00") + b"\x00" * 4
            ssh_fixture.validate_kexinit(payload)


def _ldap_search(*, base=b"", scope=b"\x00", attrs=fixture.LDAP_ATTRIBUTES):
    return (owner._ber(4, base) + owner._ber(10, scope) + owner._ber(10, b"\x00")
        + owner._ber(2, b"\x01") + owner._ber(2, b"\x02") + owner._ber(1, b"\x00")
        + owner._ber(0x87, b"objectClass") + owner._ber(0x30, b"".join(owner._ber(4, v.encode()) for v in attrs)))


def _ldap_service(case):
    service = object.__new__(owner.NetworkToolsService)
    service.case, service.deadline, service.requests = case, time.monotonic() + 10, 0
    service.condition = threading.Condition()
    return service


@pytest.mark.parametrize("case", ["ldap-ok", "ldap-empty", "ldap-referral", "ldap-malformed", "ldap-injected"])
def test_ldap_performs_only_anonymous_bind_single_base_search_and_unbind(case):
    wire = owner._ldap_reply(b"\x01", 0x60, b"\x02\x01\x03\x04\x00\x80\x00")
    wire += owner._ldap_reply(b"\x02", 0x63, _ldap_search()) + owner._ldap_reply(b"\x03", 0x42, b"")
    connection, service = _MemoryConnection(wire), _ldap_service(case)
    service._ldap(connection)
    assert service.requests == 1
    result = bytes(connection.sent)
    assert (fixture.HOSTILE_NOTE.encode() in result) is (case == "ldap-injected")
    assert (fixture.LDAP_REFERRAL.encode() in result) is (case == "ldap-referral")
    assert (b"namingContexts" in result) is (case in {"ldap-ok", "ldap-injected"})


@pytest.mark.parametrize("fault", ["credentials", "search_before_bind", "scope", "base", "attrs", "controls", "indefinite", "oversized"])
def test_ldap_rejects_authentication_search_expansion_and_unbounded_ber(fault):
    bind = owner._ldap_reply(b"\x01", 0x60, b"\x02\x01\x03\x04\x00\x80\x00")
    search = owner._ldap_reply(b"\x02", 0x63, _ldap_search())
    if fault == "credentials": bind = owner._ldap_reply(b"\x01", 0x60, b"\x02\x01\x03\x04\x01x\x80\x00")
    if fault == "search_before_bind": bind = b""
    if fault == "scope": search = owner._ldap_reply(b"\x02", 0x63, _ldap_search(scope=b"\x02"))
    if fault == "base": search = owner._ldap_reply(b"\x02", 0x63, _ldap_search(base=b"dc=other,dc=test"))
    if fault == "attrs": search = owner._ldap_reply(b"\x02", 0x63, _ldap_search(attrs=("userPassword",)))
    if fault == "controls": bind = owner._ber(0x30, owner._ber(2, b"\x01") + owner._ber(0x60, b"\x02\x01\x03\x04\x00\x80\x00") + b"\xa0\x00")
    if fault == "indefinite": bind = b"\x30\x80"
    if fault == "oversized": bind = b"\x30\x82\xff\xff"
    service = _ldap_service("ldap-ok")
    with pytest.raises(ValueError): service._ldap(_MemoryConnection(bind + search))
    assert service.requests == 0
