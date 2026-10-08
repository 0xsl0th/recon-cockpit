"""Socket-free checks of the NEW diagnostic owner, never native acceptance."""

import hashlib
import io
import json
import ssl
import subprocess
import sys
import time
import warnings

import pytest

from recon_cockpit.secure_agent import tls_posture_diagnostic_fixture as fixture


def vector(raw, width=2):
    return len(raw).to_bytes(width, "big") + raw


def extension(kind, raw):
    return kind.to_bytes(2, "big") + vector(raw)


def hello(version="tls1_3", *, name=b"harbordesk.test", extra=b"", retry=False):
    protocol, _, cipher = fixture.VERSIONS[version]
    extensions = extension(0, vector(b"\0" + vector(name))) + extension(10, b"\0\2\0\x17")
    if version == "tls1_3":
        extensions += extension(13, b"\0\2\4\3")
        extensions += extension(43, b"\2\3\4")
        extensions += extension(51, vector(b"\0\x17" + vector(b"\4" + b"x" * 64)))
        if retry:
            extensions += extension(44, vector(fixture.COOKIE))
    extensions += extra
    body = min(protocol, 0x0303).to_bytes(2, "big") + b"r" * 32 + vector(b"", 1)
    body += vector(cipher.to_bytes(2, "big") + b"\0\xff") + b"\1\0" + vector(extensions)
    message = b"\1" + len(body).to_bytes(3, "big") + body
    return b"\x16\3\1" + vector(message)


class Wire:
    def __init__(self, raw, fragment=None):
        self.source, self.sent, self.timeouts = io.BytesIO(raw), bytearray(), []
        self.fragment = fragment

    def recv(self, size):
        return self.source.read(min(size, self.fragment) if self.fragment else size)

    def sendall(self, raw):
        self.sent.extend(raw)

    def settimeout(self, value):
        self.timeouts.append(value)


@pytest.mark.parametrize("version", fixture.VERSIONS)
def test_complete_client_hello_validates_all_declared_version_fields(version):
    raw = hello(version)
    value = fixture.validate_client_hello(raw, version)
    assert value["version"] == version
    assert value["sha256"] == hashlib.sha256(raw).hexdigest()
    for other in fixture.VERSIONS:
        if other != version:
            with pytest.raises(ValueError):
                fixture.validate_client_hello(raw, other)


@pytest.mark.parametrize("name", [b"127.0.0.1", b"other.test", b"harbordesk.test\0", b"", b"a" * 256])
def test_wrong_sni_never_acknowledges_a_request(name):
    wire, ledger, progress = Wire(hello(name=name)), fixture.new_ledger("reject", "tls1_3"), []
    with pytest.raises(ValueError):
        fixture.serve(wire, case="reject", version="tls1_3", deadline=time.monotonic() + 1,
                      context=None, ledger=ledger, on_request=lambda: progress.append(1))
    assert progress == [] and not wire.sent and ledger["client_hellos"] == 0


@pytest.mark.parametrize("extra", [extension(0, b""), extension(16, b""), extension(41, b""),
                                  extension(42, b""), extension(35, b""), extension(65500, b""),
                                  extension(22, b"x"), extension(13, b"\0\1\4"), b"\0"])
def test_duplicate_unknown_or_malformed_extensions_refuse(extra):
    with pytest.raises(ValueError):
        fixture.validate_client_hello(hello(extra=extra), "tls1_3")


@pytest.mark.parametrize("position", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 43, 44, 45, 46])
def test_header_version_and_vector_length_mutations_refuse(position):
    raw = bytearray(hello())
    raw[position] ^= 0x80
    with pytest.raises(ValueError):
        fixture.validate_client_hello(bytes(raw), "tls1_3")


@pytest.mark.parametrize("length", [0, 1, 4, 5, 8, 10, 49, 4097])
def test_incomplete_and_oversized_client_hello_refuse(length):
    with pytest.raises(ValueError):
        fixture.validate_client_hello((hello() + b"x" * 4097)[:length], "tls1_3")


def test_retry_cookie_only_allowed_in_explicit_second_hello():
    with pytest.raises(ValueError):
        fixture.validate_client_hello(hello(retry=True), "tls1_3")
    with pytest.raises(ValueError):
        fixture.validate_client_hello(hello(), "tls1_3", retry=True)
    assert fixture.validate_client_hello(hello(retry=True), "tls1_3", retry=True)["version"] == "tls1_3"


def test_tls13_exact_psk_mode_advertisement_never_allows_psk_material():
    advertisement = extension(45, b"\1\1")
    assert 45 in fixture.validate_client_hello(hello(extra=advertisement), "tls1_3")["extension_types"]
    for modes in (b"", b"\1\0", b"\1\2", b"\2\0\1", b"\1\1\0"):
        with pytest.raises(ValueError, match="psk_modes"):
            fixture.validate_client_hello(hello(extra=extension(45, modes)), "tls1_3")
    for extra in (advertisement + extension(41, b"\0\0"), advertisement + extension(42, b"")):
        with pytest.raises(ValueError, match="extension"):
            fixture.validate_client_hello(hello(extra=extra), "tls1_3")
    for version in ("tls1", "tls1_1", "tls1_2"):
        with pytest.raises(ValueError, match="supported_version"):
            fixture.validate_client_hello(hello(version, extra=advertisement), version)


@pytest.mark.parametrize("version", fixture.VERSIONS)
@pytest.mark.parametrize("fragment", [None, 1, 3])
def test_explicit_reject_records_only_a_sent_alert_and_full_received_hello(version, fragment):
    raw, ledger, progress = hello(version), fixture.new_ledger("reject", version), []
    wire = Wire(raw, fragment)
    fixture.serve(wire, case="reject", version=version, deadline=time.monotonic() + 2,
                  context=None, ledger=ledger, on_request=lambda: progress.append(1))
    assert progress == [1] and ledger["client_hellos"] == 1
    assert wire.sent == b"\x15\3\3\0\2\2\x46"
    assert ledger["received_bytes"] == len(raw) and ledger["sent_bytes"] == 7
    assert ledger["received_records"][0]["raw_hex"] == raw.hex()
    assert ledger["alerts"] == [{"direction": "write", "type": 2, "description": 70}]
    assert ledger["handshake_completed"] is False and ledger["clean_close"] is False


def test_hrr_records_second_hello_as_observed_boundary_failure_not_blocked():
    raw = hello() + b"\x14\3\3\0\1\1" + hello(retry=True)
    ledger, wire, progress = fixture.new_ledger("hrr", "tls1_3"), Wire(raw), []
    with pytest.raises(ValueError, match="observed_not_blocked"):
        fixture.serve(wire, case="hrr", version="tls1_3", deadline=time.monotonic() + 2,
                      context=None, ledger=ledger, on_request=lambda: progress.append(1))
    assert progress == [1] and ledger["client_hellos"] == 2 and ledger["hrr_sent"]
    assert fixture.HRR_RANDOM in wire.sent and fixture.COOKIE in wire.sent
    assert [item["type"] for item in ledger["received_records"]] == [22, 20, 22]
    assert [item["type"] for item in ledger["handshake_messages"]] == [1, 2, 1]


@pytest.mark.parametrize("header", [b"\x16\3\1\xff\xff", b"\x16\3\1\0\0"])
def test_owner_rejects_declared_payload_limit_before_reading_payload(header):
    wire, ledger = Wire(header + b"do not read"), fixture.new_ledger("reject", "tls1_3")
    with pytest.raises(ValueError, match="byte_cap"):
        fixture.RecordIO(wire, time.monotonic() + 1, ledger).receive()
    assert wire.source.tell() == 5 and ledger["received_bytes"] == 5


def test_owner_aggregate_byte_and_record_limits_prevent_additional_reads_or_sends():
    raw, ledger = b"\x15\3\3\0\2\2\x46", fixture.new_ledger("reject", "tls1_3")
    wire = Wire(raw)
    records = fixture.RecordIO(wire, time.monotonic() + 1, ledger)
    ledger["received_bytes"] = fixture.MAX_DIRECTION_BYTES - 4
    with pytest.raises(ValueError, match="byte_cap"):
        records.receive()
    assert wire.source.tell() == 0
    ledger["sent_bytes"] = fixture.MAX_DIRECTION_BYTES - 6
    with pytest.raises(ValueError, match="byte_cap"):
        records.send(raw)
    assert not wire.sent
    ledger["received_bytes"] = 0
    ledger["received_records"] = [{}] * fixture.MAX_RECORDS
    with pytest.raises(ValueError, match="record_cap"):
        records.receive()
    assert wire.source.tell() == 0


class MemoryClient(Wire):
    """Real OpenSSL SSLObject client; no sockets, CLI or external process."""
    def __init__(self, version, *, application=b"", ragged=False):
        super().__init__(b"")
        self.pending = bytearray()
        self.inbound, self.outbound = ssl.MemoryBIO(), ssl.MemoryBIO()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = context.maximum_version = fixture.VERSIONS[version][1]
        context.set_ciphers("ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0" if version in ("tls1", "tls1_1")
                            else "ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=2")
        context.set_ecdh_curve("prime256v1")
        context.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_TICKET | ssl.OP_NO_RENEGOTIATION
        context.load_verify_locations(cadata=fixture.public.TLS_CERTIFICATE_CA_PEM.decode("ascii"))
        self.client = context.wrap_bio(self.inbound, self.outbound, server_hostname=fixture.public.TLS_NAME)
        self.handshake, self.closed, self.application, self.ragged = False, False, application, ragged
        self.advance()

    def advance(self):
        try:
            if not self.handshake:
                self.client.do_handshake()
                self.handshake = True
                if self.application:
                    self.client.write(self.application)
            if self.handshake and not self.ragged and not self.closed:
                self.client.unwrap()
                self.closed = True
        except ssl.SSLWantReadError:
            pass
        self.pending.extend(self.outbound.read())

    def recv(self, size):
        raw = bytes(self.pending[:size])
        del self.pending[:size]
        return raw

    def sendall(self, raw):
        self.sent.extend(raw)
        self.inbound.write(raw)
        self.advance()


@pytest.mark.parametrize("version", ["tls1", "tls1_1", "tls1_2"])
def test_actual_legacy_and_modern_memory_tls_handshakes_and_clean_close(version):
    # Python SSLContext lacks a public TLS 1.3 ciphersuite setter; the native
    # fixed-argv corpus must prove its exact TLS 1.3 ClientHello separately.
    ledger, progress = fixture.new_ledger("legacy", version), []
    context, wire = fixture.tls_context("legacy", ledger), MemoryClient(version)
    fixture.serve(wire, case="legacy", version=version, deadline=time.monotonic() + 3,
                  context=context, ledger=ledger, on_request=lambda: progress.append(1))
    assert progress == [1] and ledger["handshake_completed"] and ledger["clean_close"]
    assert ledger["application_bytes"] == 0 and wire.handshake and wire.closed
    assert ledger["client_hellos"] == 1 and ledger["received_bytes"] <= fixture.MAX_DIRECTION_BYTES
    finished = [item for item in ledger["handshake_messages"] if item["type"] == 20]
    assert {(item["direction"], item["length"]) for item in finished} == {("read", 16), ("write", 16)}
    association = ledger["server_close_notify_record"]
    assert association["sent_record_index"] == len(ledger["sent_records"]) - 1
    record = ledger["sent_records"][association["sent_record_index"]]
    assert association["raw_sha256"] == hashlib.sha256(bytes.fromhex(record["raw_hex"])).hexdigest()
    assert association["payload_length"] == record["payload_length"]
    assert ledger["alerts"][-1] == {"direction": "write", "type": 1, "description": 0}


@pytest.mark.parametrize("application,ragged", [(b"GET / HTTP/1.0\r\n\r\n", False), (b"", True)])
def test_application_or_ragged_eof_cannot_claim_clean_completion(application, ragged):
    ledger = fixture.new_ledger("legacy", "tls1_2")
    context, wire = fixture.tls_context("legacy", ledger), MemoryClient("tls1_2", application=application, ragged=ragged)
    with pytest.raises(ValueError, match="application_data|eof"):
        fixture.serve(wire, case="legacy", version="tls1_2", deadline=time.monotonic() + 2,
                      context=context, ledger=ledger, on_request=lambda: None)
    assert ledger["handshake_completed"] and not ledger["clean_close"]
    assert ledger["application_bytes"] == bool(application)
    assert ledger["server_close_notify_record"] is None


def test_owner_context_policies_remain_consistent_across_requested_versions():
    for case in ("modern", "legacy"):
        context = fixture.tls_context(case, fixture.new_ledger(case, "tls1_2"))
        assert context.minimum_version == (ssl.TLSVersion.TLSv1 if case == "legacy" else ssl.TLSVersion.TLSv1_2)
        assert context.maximum_version == ssl.TLSVersion.TLSv1_3
        assert context.num_tickets == 0
        assert context.security_level == (0 if case == "legacy" else 2)


@pytest.mark.parametrize("changes", [{"case": "unknown"}, {"version": "tls1_4"}, {"case": "hrr", "version": "tls1"},
                                     {"deadline": float("inf")}, {"deadline": False}, {"extra": 1}])
def test_owner_request_rejects_unknown_scope_and_unbounded_deadline(changes):
    request = {"case": "modern", "version": "tls1_3", "deadline": time.monotonic() + 5, "host_namespaces": {}}
    request.update(changes)
    with pytest.raises(ValueError):
        fixture.read_request(io.BytesIO(json.dumps(request).encode() + b"\n"))


def test_standalone_owner_import_resolves_only_reviewed_sibling_modules():
    code = ("import importlib.util; s=importlib.util.spec_from_file_location('owner',%r); "
            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
            "assert m.DiagnosticOwner().service_port({}) == 8080") % fixture.__file__
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code], capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("case,version,deadline", [("invalid", "tls1", 1), ("modern", "invalid", 1),
                                                  ("hrr", "tls1", 1), ("reject", "tls1", float("nan")),
                                                  ("reject", "tls1", 0)])
def test_invalid_scope_or_deadline_refuses_before_receiving(case, version, deadline):
    wire = Wire(hello("tls1"))
    with pytest.raises(ValueError):
        fixture.serve(wire, case=case, version=version, deadline=deadline, context=None,
                      ledger={}, on_request=lambda: pytest.fail("unexpected progress"))
    assert wire.source.tell() == 0 and not wire.sent
