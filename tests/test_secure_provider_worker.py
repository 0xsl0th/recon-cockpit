"""Portable transport mechanics, without sockets or claims of Linux isolation."""

import base64
import errno
import hashlib
import io
import json
import ssl
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import provider_contract as contract
from recon_cockpit.secure_agent import provider_lab_worker as lab
from recon_cockpit.secure_agent import provider_worker as worker


CREDENTIAL = "synthetic-" + "a" * 64
HOST = {name: f"{name}:[100]" for name in worker.NAMESPACE_NAMES}
LAB = {name: f"{name}:[200]" for name in worker.NAMESPACE_NAMES}
REQUEST = contract.build_request(b'{"step":1,"untrusted_observation":null}')
CA = "-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----\n"


def launch():
    return {"schema_version": "1", "request": REQUEST.decode(), "credential": CREDENTIAL,
            "ca_pem": CA, "deadline": 100.0, "host_namespaces": dict(HOST), "lab_namespaces": dict(LAB)}


def validate(value):
    raw = contract.encode(value)
    return worker.validate_launch(raw, hashlib.sha256(raw).hexdigest())


def test_launch_requires_exact_private_payload_commitment():
    value = launch()
    assert validate(value) == value
    raw = contract.encode(value)
    with pytest.raises(ValueError, match="^provider_launch_mismatch$"):
        worker.validate_launch(raw + b" ", hashlib.sha256(raw).hexdigest())
    with pytest.raises(ValueError, match="^provider_launch_mismatch$"):
        worker.validate_launch(raw, "a" * 63)


@pytest.mark.parametrize("field,value", [
    ("schema_version", 1), ("credential", "real-secret"), ("credential", CREDENTIAL + "\r\nInjected: yes"),
    ("request", "{}"), ("ca_pem", "system"), ("ca_pem", CA + "unexpected trailing text"),
    ("deadline", True), ("deadline", 0), ("deadline", "100"),
    ("host_namespaces", {}), ("lab_namespaces", HOST), ("url", "https://example.invalid"),
])
def test_launch_rejects_credential_endpoint_and_namespace_substitutions(field, value):
    data = launch()
    data[field] = value
    with pytest.raises((ValueError, contract.ProviderError)):
        validate(data)


@pytest.mark.parametrize("raw", [
    b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e9999}', b'{"x":"\\ud800"}', b"[]",
    b'{"x":' + b"[" * 34 + b"0" + b"]" * 34 + b"}",
])
def test_json_transport_rejects_ambiguous_or_unbounded_values(raw):
    with pytest.raises((ValueError, UnicodeError)):
        worker._decode(raw)


def test_descriptor_check_requires_no_live_handle_beyond_standard_streams(monkeypatch):
    monkeypatch.setattr(worker.os, "listdir", lambda _: ["0", "1", "2", "3"])
    monkeypatch.setattr(worker.os, "fstat", lambda _: SimpleNamespace())
    with pytest.raises(RuntimeError, match="^provider_inherited_descriptor$"):
        worker.assert_private_descriptors()

    def fail(number):
        def fstat(_fd):
            raise OSError(number, "private detail")
        return fstat

    monkeypatch.setattr(worker.os, "fstat", fail(errno.EBADF))
    worker.assert_private_descriptors()
    monkeypatch.setattr(worker.os, "fstat", fail(errno.EACCES))
    with pytest.raises(RuntimeError, match="^provider_descriptor_check_failed$"):
        worker.assert_private_descriptors()


@pytest.fixture
def namespace_state(monkeypatch):
    state = {"uid": 0, "gid": 0, "mapping": "0 0 1\n", "interfaces": [(1, "lo")],
             "current": {name: f"{name}:[300]" for name in HOST} | {"net": LAB["net"]}, "caps": "0"}
    monkeypatch.setattr(worker.sys, "platform", "linux")
    monkeypatch.setattr(worker.os, "getuid", lambda: state["uid"])
    monkeypatch.setattr(worker.os, "getgid", lambda: state["gid"])
    monkeypatch.setattr(worker.os, "readlink", lambda path: state["current"][path.rsplit("/", 1)[1]])
    monkeypatch.setattr(worker.socket, "if_nameindex", lambda: state["interfaces"])
    monkeypatch.setattr(worker, "open", lambda *_a, **_k: io.StringIO(state["mapping"]), raising=False)
    monkeypatch.setattr(worker.worker, "_status", lambda: {"CapEff": state["caps"]})
    return state


def test_only_lab_network_may_be_shared_with_nested_worker(namespace_state):
    worker.assert_lab_namespaces(HOST, LAB)


@pytest.mark.parametrize("change", [
    {"uid": 1000}, {"gid": 1000}, {"mapping": "0 1000 1\n"}, {"mapping": "0 0 2\n"},
    {"interfaces": [(1, "lo"), (2, "eth0")]}, {"caps": "1000"},
])
def test_worker_identity_interfaces_or_net_admin_capability_refuse_startup(namespace_state, change):
    namespace_state.update(change)
    with pytest.raises(RuntimeError):
        worker.assert_lab_namespaces(HOST, LAB)


@pytest.mark.parametrize("name", worker.NAMESPACE_NAMES)
def test_worker_never_shares_host_namespace(namespace_state, name):
    namespace_state["current"][name] = HOST[name]
    with pytest.raises(RuntimeError, match="^provider_namespace_mismatch$"):
        worker.assert_lab_namespaces(HOST, LAB)


@pytest.mark.parametrize("name", worker.NAMESPACE_NAMES)
def test_nested_namespaces_require_exactly_the_owned_network(namespace_state, name):
    namespace_state["current"][name] = LAB[name] if name != "net" else "net:[300]"
    with pytest.raises(RuntimeError, match="^provider_namespace_mismatch$"):
        worker.assert_lab_namespaces(HOST, LAB)


class Connection:
    def __init__(self, data, chunk=4096):
        self.source = io.BytesIO(data)
        self.chunk = chunk
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv(self, size):
        return self.source.read(min(size, self.chunk))


def wire(body=None, *, status="200 Owned", headers=(), length=None):
    body = contract.success_response() if body is None else body
    fields = [f"HTTP/1.1 {status}".encode(),
              f"Content-Length: {len(body) if length is None else length}".encode(),
              b"Content-Type: application/json", *headers]
    return b"\r\n".join(fields) + b"\r\n\r\n" + body


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    monkeypatch.setattr(worker.time, "monotonic", lambda: 10.0)


@pytest.mark.parametrize("chunk", [1, 17, 4096])
def test_response_framing_accepts_fragmented_json_and_requires_eof(chunk):
    connection = Connection(wire(), chunk)
    assert worker.read_response(connection, 100, CREDENTIAL) == contract.success_response()
    assert connection.timeouts and set(connection.timeouts) == {90.0}


@pytest.mark.parametrize("raw,code", [
    (wire(headers=[b"content-length: 1"]), "malformed_response"),
    (wire(headers=[b"Transfer-Encoding: chunked"]), "malformed_response"),
    (wire(headers=[b"Content-Encoding: gzip"]), "malformed_response"),
    (wire(headers=[b"X-Header : value"]), "malformed_response"),
    (wire(headers=[b"X-Header: value\tinvalid"]), "malformed_response"),
    (wire(headers=[b" folded-header"]), "malformed_response"),
    (wire(length="01"), "malformed_response"),
    (wire(length="+1"), "malformed_response"),
    (wire(length=65537), "response_too_large"),
    (wire(length=65536), "malformed_response"),
    (wire() + b"additional bytes", "malformed_response"),
    (wire()[:-1], "malformed_response"),
    (wire().replace(b"HTTP/1.1", b"HTTP/1.0"), "malformed_response"),
    (wire().replace(b"application/json", b"text/html"), "malformed_response"),
    (b"HTTP/1.1 200 Owned\r\nX: " + b"a" * 8192, "response_too_large"),
    (wire(b'{"x":1,"x":2}'), "malformed_response"),
    (wire(b'{"x":NaN}'), "malformed_response"),
    (wire(b'{"x":"\\ud800"}'), "malformed_response"),
    (wire(b"[]"), "malformed_response"),
    (wire(status="302 Owned", headers=[b"Location: https://external.invalid"]), "http_error"),
    (wire(status="429 Owned", headers=[b"Retry-After: 0"]), "http_error"),
])
def test_http_failures_are_closed_static_errors(raw, code):
    with pytest.raises(worker.TransportFailure) as error:
        worker.read_response(Connection(raw), 100, CREDENTIAL)
    assert error.value.code == code
    assert str(error.value) == code


@pytest.mark.parametrize("scenario,expected", [
    ("success", None), ("redirect", "http_error"), ("rate_limit", "http_error"),
    ("oversized", "response_too_large"), ("truncated", "malformed_response"),
    ("malformed", "malformed_response"), ("credential_echo", "credential_reflection"),
    ("escaped_credential_echo", "credential_reflection"),
])
def test_owned_fixture_exercises_documented_transport_outcomes(scenario, expected):
    connection = Connection(lab.response(scenario, CREDENTIAL))
    if expected is None:
        assert worker.read_response(connection, 100, CREDENTIAL) == contract.success_response()
    else:
        with pytest.raises(worker.TransportFailure) as error:
            worker.read_response(connection, 100, CREDENTIAL)
        assert error.value.code == expected
        assert CREDENTIAL not in str(error.value)


@pytest.mark.parametrize("layers", [1, 2, 4])
def test_credential_reflection_rejects_mixed_literal_and_json_escaped_strings(layers):
    escaped = "synthetic-" + "".join("\\" * layers + "u0061" for _ in range(64))
    raw = ('{"echo":"' + escaped + '"}').encode()
    assert worker._credential_reflected(raw, CREDENTIAL)
    with pytest.raises(worker.TransportFailure, match="^credential_reflection$"):
        worker.read_response(Connection(wire(raw)), 100, CREDENTIAL)


def test_expired_deadline_prevents_receive_and_late_parse_cannot_succeed(monkeypatch):
    connection = SimpleNamespace(settimeout=lambda _: pytest.fail("expired transport touched socket"))
    with pytest.raises(worker.TransportFailure, match="^deadline_exceeded$"):
        worker.read_response(connection, 10, CREDENTIAL)
    original = worker._decode

    def late_decode(raw):
        result = original(raw)
        monkeypatch.setattr(worker.time, "monotonic", lambda: 101.0)
        return result

    monkeypatch.setattr(worker, "_decode", late_decode)
    with pytest.raises(worker.TransportFailure, match="^deadline_exceeded$"):
        worker.read_response(Connection(wire()), 100, CREDENTIAL)


def test_one_fixed_verified_tls_post_matches_owned_server_contract(monkeypatch):
    events = []
    response = Connection(wire())
    sent = []

    class Raw:
        def settimeout(self, value):
            events.append(("timeout", value))

        def connect(self, address):
            events.append(("connect", address))

        def close(self):
            events.append(("close",))

    raw = Raw()

    class TLS:
        settimeout = response.settimeout
        recv = response.recv

        def __enter__(self):
            return self

        def __exit__(self, *_):
            events.append(("tls_closed",))

        def do_handshake(self):
            events.append(("handshake",))

        def selected_alpn_protocol(self):
            return "http/1.1"

        def sendall(self, data):
            sent.append(data)

    class Context:
        def load_verify_locations(self, **kwargs):
            assert kwargs == {"cadata": CA}
            events.append(("ca",))

        def set_alpn_protocols(self, protocols):
            assert protocols == ["http/1.1"]

        def wrap_socket(self, source, **kwargs):
            assert source is raw
            assert kwargs == {"server_hostname": contract.TLS_NAME, "do_handshake_on_connect": False}
            return TLS()

    context = Context()

    def make_context(protocol):
        assert protocol == ssl.PROTOCOL_TLS_CLIENT
        return context

    def make_socket(family, kind):
        assert family == worker.socket.AF_INET and kind == worker.socket.SOCK_STREAM
        return raw

    monkeypatch.setattr(worker.ssl, "SSLContext", make_context)
    monkeypatch.setattr(worker.socket, "socket", make_socket)
    monkeypatch.setattr(worker.socket, "getaddrinfo", lambda *_a, **_k: pytest.fail("DNS must be unavailable"))
    monkeypatch.setenv("HTTPS_PROXY", "https://must-not-be-used.invalid")
    monkeypatch.setenv("OPENAI_API_KEY", "SYNTHETIC-UNUSED-ENVIRONMENT-CANARY")
    assert worker.tls_exchange(REQUEST, CREDENTIAL, CA, 100) == contract.success_response()
    assert context.check_hostname is True and context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert events.count(("connect", ("127.0.0.1", 8443))) == 1
    assert events.count(("handshake",)) == 1 and events[-1] == ("close",)
    assert len(sent) == 1
    assert lab._http_request(Connection(sent[0], chunk=1), CREDENTIAL) == REQUEST
    assert b"SYNTHETIC-UNUSED-ENVIRONMENT-CANARY" not in sent[0]


def request_wire():
    return (f"POST /v1/responses HTTP/1.1\r\nHost: provider.owned.invalid:8443\r\n"
            f"Authorization: Bearer {CREDENTIAL}\r\nContent-Type: application/json\r\n"
            f"Accept: application/json\r\nConnection: close\r\nContent-Length: {len(REQUEST)}\r\n\r\n"
            ).encode() + REQUEST


@pytest.mark.parametrize("before,after", [
    (b"POST /v1/responses", b"POST https://external.invalid/v1/responses"),
    (b"Host: provider.owned.invalid:8443", b"Host: external.invalid"),
    (CREDENTIAL.encode(), b"another synthetic credential"),
    (b"Accept: application/json\r\n", b""),
    (b"Accept: application/json", b"Accept: text/plain"),
    (b"Connection: close", b"Transfer-Encoding: chunked\r\nConnection: close"),
    (b"Connection: close", b"connection: close\r\nConnection: close"),
    (b"Connection: close", b"Connection: close\t"),
    (b"Content-Length: ", b"Content-Length: 0"),
])
def test_owned_server_refuses_destination_authentication_and_framing_changes(before, after):
    with pytest.raises(ValueError):
        lab._http_request(Connection(request_wire().replace(before, after)), CREDENTIAL)


def test_owned_server_rejects_incomplete_or_surplus_body():
    for raw in (request_wire()[:-1], request_wire() + b"extra", b"x" * 8192):
        with pytest.raises(ValueError):
            lab._http_request(Connection(raw), CREDENTIAL)


@pytest.fixture
def isolated_bootstrap(monkeypatch):
    calls = []
    monkeypatch.setattr(worker, "assert_lab_namespaces", lambda *_: calls.append("namespaces"))
    monkeypatch.setattr(worker.worker, "_set_limits", lambda *_: calls.append("limits"))
    monkeypatch.setattr(worker.worker, "drop_privileges", lambda: calls.append("privileges"))
    monkeypatch.setattr(worker.resource, "setrlimit", lambda *_: None)
    monkeypatch.setattr(worker.worker, "install_syscall_filter", lambda: calls.append("seccomp"))
    checks = {name: True for name in ("forbidden_ip_blocked", "forbidden_port_blocked",
                                     "namespace_creation_blocked", "capabilities_dropped")}
    monkeypatch.setattr(worker.worker, "verify_network_boundary", lambda port: dict(checks) if port == 8443 else {})
    monkeypatch.setattr(worker.planner_worker, "_process_creation_blocked", lambda: None)
    monkeypatch.setattr(worker.planner_worker, "_root_read_only", lambda: None)
    status = {name: "0" for name in worker.CAPABILITY_FIELDS} | {"NoNewPrivs": "1"}
    monkeypatch.setattr(worker.worker, "_status", lambda: status)
    return calls, checks, status


@pytest.mark.parametrize("failure,expected", [
    (ssl.SSLError("PRIVATE CA DETAIL"), "tls_error"),
    (OSError("PRIVATE HOST DETAIL"), "transport_error"),
    (TimeoutError("PRIVATE TIMING DETAIL"), "deadline_exceeded"),
    (worker.TransportFailure("http_error", 429), "http_error"),
])
def test_execution_sanitizes_transport_failures_after_complete_boundary(isolated_bootstrap, monkeypatch, failure, expected):
    def exchange(*_):
        assert isolated_bootstrap[0] == ["namespaces", "limits", "privileges", "seccomp"]
        raise failure

    monkeypatch.setattr(worker, "tls_exchange", exchange)
    result = worker.execute(launch())
    assert result["status"] == expected and result["response"] is None
    assert result["boundary_checks"] == dict.fromkeys(contract.BOUNDARY_NAMES, True)
    assert "PRIVATE" not in json.dumps(result) and CREDENTIAL not in json.dumps(result)


def test_failed_boundary_never_reaches_credential_exchange(isolated_bootstrap, monkeypatch):
    isolated_bootstrap[1]["forbidden_port_blocked"] = False
    monkeypatch.setattr(worker, "tls_exchange", lambda *_: pytest.fail("incomplete boundary sent credential"))
    with pytest.raises(RuntimeError, match="^provider_boundary_incomplete$"):
        worker.execute(launch())


def test_success_envelope_contains_only_validated_response_and_boundary(isolated_bootstrap, monkeypatch):
    monkeypatch.setattr(worker, "tls_exchange", lambda *_: contract.success_response())
    result = worker.execute(launch())
    assert base64.b64decode(result["response"], validate=True) == contract.success_response()
    assert result["status"] == "ok" and result["http_status"] == 200
    assert CREDENTIAL not in json.dumps(result) and CA not in json.dumps(result)


def test_owner_bootstrap_is_closed_synthetic_configuration():
    value = {"scenario": "success", "credential": CREDENTIAL, "deadline": 100.0, "host_namespaces": HOST}
    assert lab.read_request(io.BytesIO(contract.encode(value) + b"\n")) == value
    for key, invalid in (("scenario", "public-provider"), ("credential", "real-key"),
                         ("deadline", 700), ("deadline", True), ("host_namespaces", LAB | {"user": "net:[200]"}),
                         ("url", "https://example.invalid")):
        with pytest.raises(ValueError):
            lab.read_request(io.BytesIO(contract.encode(value | {key: invalid}) + b"\n"))
