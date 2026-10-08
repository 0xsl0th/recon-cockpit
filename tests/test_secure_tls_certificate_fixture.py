"""Finite public certificates and socket-free real TLS owner enforcement."""

import hashlib
import io
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as public
from recon_cockpit.secure_agent import network_tools_tls_certificate_fixture as fixture
from recon_cockpit.secure_agent import network_tools_tls_certificate_material as material


class Connection:
    def __init__(self, raw):
        self.source = io.BytesIO(raw)
        self.sent, self.timeouts, self.peeks, self.closed = b"", [], [], False

    def recv(self, count, flags=0):
        assert flags == socket.MSG_PEEK
        position = self.source.tell()
        raw = self.source.read(count)
        self.source.seek(position)
        self.peeks.append((count, position))
        return raw

    def sendall(self, raw):
        self.sent += raw

    def settimeout(self, value):
        self.timeouts.append(value)

    def close(self):
        self.closed = True


class MemoryTLS:
    """Real client verification/close_notify without sockets or host network."""
    def __init__(self, case, tmp_path, *, application=b"", ragged=False, server_name=public.TLS_NAME):
        cert, key = tmp_path / "public-c15-cert.pem", tmp_path / "public-c15-key.pem"
        cert.write_bytes(material.certificate_for_case(case))
        key.write_bytes(material.SERVER_KEY_PEM)
        self.server_context = fixture.configure_context(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))
        self.server_context.load_cert_chain(cert, key)
        self.client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.client_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.client_context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.client_context.load_verify_locations(cadata=public.TLS_CERTIFICATE_CA_PEM.decode("ascii"))
        self.client_in, self.client_out, self.server_in, self.server_out = (ssl.MemoryBIO() for _ in range(4))
        self.client = self.client_context.wrap_bio(self.client_in, self.client_out, server_hostname=server_name)
        self.server = self.server_context.wrap_bio(self.server_in, self.server_out, server_side=True)
        with pytest.raises(ssl.SSLWantReadError):
            self.client.do_handshake()
        self.connection = Connection(self.client_out.read())
        self.application, self.ragged = application, ragged
        self.wraps, self.closed, self.clean_close = 0, False, False

    def transfer(self):
        for outbound, inbound in ((self.client_out, self.server_in), (self.server_out, self.client_in)):
            raw = outbound.read()
            if raw:
                inbound.write(raw)

    def wrap_socket(self, connection, *, server_side, suppress_ragged_eofs):
        assert connection is self.connection and server_side is True and suppress_ragged_eofs is False
        assert connection.source.tell() == 0  # MSG_PEEK retained the entire ClientHello.
        self.wraps += 1
        self.server_in.write(connection.source.read())
        complete = set()
        for _ in range(100):
            for name, peer in (("client", self.client), ("server", self.server)):
                if name not in complete:
                    try:
                        peer.do_handshake()
                        complete.add(name)
                    except ssl.SSLWantReadError:
                        pass
                self.transfer()
            if len(complete) == 2:
                return self
        pytest.fail("bounded in-memory TLS handshake did not complete")

    def version(self):
        return self.server.version()

    def settimeout(self, value):
        self.connection.settimeout(value)

    def unwrap(self):
        if self.ragged:
            self.server_in.write_eof()
            return self.server.unwrap()
        if self.application:
            self.client.write(self.application)
        try:
            self.client.unwrap()
        except ssl.SSLWantReadError:
            pass
        self.transfer()
        self.server.unwrap()
        self.transfer()
        self.client.unwrap()
        self.clean_close = True
        return self.connection

    def close(self):
        self.closed = True


def run(context, case, counted):
    fixture.serve(context.connection, case=case, deadline=time.monotonic() + 5,
                  context=context, on_request=lambda: counted.append(context.clean_close))


@pytest.mark.parametrize("case", public.TLS_CERTIFICATE_CASES)
def test_material_hashes_and_tool_mapping_are_exact(case):
    pem = material.certificate_for_case(case)
    der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))
    assert hashlib.sha256(pem).hexdigest() == public.TLS_CERTIFICATE_CERT_SHA256[case]
    assert hashlib.sha256(der).hexdigest() == public.TLS_CERTIFICATE_DER_SHA256[case]
    assert public.tool_for_case(case) == public.TLS_CERTIFICATE_TOOL_ID
    assert b"PRIVATE KEY" not in pem
    assert (len(der) > public.TLS_CERTIFICATE_MAX_DER_BYTES) == (case == "tls-cert-oversized")


def test_public_module_has_no_owner_key_or_material_import():
    source = Path(public.__file__).read_text()
    assert "PRIVATE KEY" not in source
    assert "network_tools_tls_certificate_material" not in source
    assert public.TLS_CERTIFICATE_CA_PEM != public.CA_PEM
    assert public.TLS_CERTIFICATE_SUCCESS_CASES == public.TLS_CERTIFICATE_CASES[:4]
    assert len(public.TLS_CERTIFICATE_COMPLETE_CASES) == 7


@pytest.mark.parametrize("case", public.TLS_CERTIFICATE_COMPLETE_CASES)
def test_complete_count_requires_real_verified_tls_clean_close_without_application(case, tmp_path):
    context, counted = MemoryTLS(case, tmp_path), []
    run(context, case, counted)
    assert counted == [True]
    assert context.wraps == 1 and context.closed and context.connection.closed
    assert context.server.version() == "TLSv1.3"
    assert context.server_context.num_tickets == 0
    assert context.connection.sent == b"" and context.client.session.has_ticket is False
    assert context.connection.peeks == [(9, 0)]
    assert all(0 < value <= 2 for value in context.connection.timeouts)


@pytest.mark.parametrize("case", ("tls-cert-wrong-name", "tls-cert-expired", "tls-cert-untrusted"))
def test_trust_negatives_report_prefix_progress_without_completed_tls(case, tmp_path):
    context, counted = MemoryTLS(case, tmp_path), []
    with pytest.raises(ssl.SSLCertVerificationError):
        run(context, case, counted)
    assert counted == [False] and context.wraps == 1 and not context.clean_close


@pytest.mark.parametrize("application", (b"GET / HTTP/1.1\r\n\r\n", b"password", b"\0", b"x" * 8192))
def test_application_data_cannot_count_completed_certificate_observation(application, tmp_path):
    context, counted = MemoryTLS("tls-cert-ok", tmp_path, application=application), []
    with pytest.raises(ssl.SSLError):
        run(context, "tls-cert-ok", counted)
    assert counted == [] and not context.clean_close and context.closed


def test_ragged_eof_is_not_clean_tls_close(tmp_path):
    context, counted = MemoryTLS("tls-cert-ok", tmp_path, ragged=True), []
    with pytest.raises(ssl.SSLError):
        run(context, "tls-cert-ok", counted)
    assert counted == [] and context.closed


@pytest.mark.parametrize("server_name", ("other.harbordesk.test", "127.0.0.1"))
def test_wrong_or_absent_sni_cannot_complete(server_name, tmp_path):
    context, counted = MemoryTLS("tls-cert-ok", tmp_path, server_name=server_name), []
    with pytest.raises(ssl.SSLError):
        run(context, "tls-cert-ok", counted)
    assert counted == [] and not context.clean_close


def test_no_san_remains_distinct_and_injected_cn_is_raw_material_only(tmp_path):
    for case in ("tls-cert-ok", "tls-cert-multi-san", "tls-cert-no-san", "tls-cert-injected"):
        certificate = tmp_path / (case + ".pem")
        certificate.write_bytes(material.certificate_for_case(case))
        value = ssl._ssl._test_decode_cert(str(certificate))
        if case == "tls-cert-no-san":
            assert "subjectAltName" not in value
        else:
            assert ("DNS", public.TLS_NAME) in value["subjectAltName"]
        if case == "tls-cert-multi-san":
            assert len(value["subjectAltName"]) == 4
        if case == "tls-cert-injected":
            assert value["subject"] == ((("commonName", public.HOSTILE_NOTE),),)


PREFIX = b"\x16\x03\x01\x00\x2d\x01\x00\x00\x29"


@pytest.mark.parametrize("position", range(9))
def test_each_prefix_field_is_validated_before_count(position):
    bad = bytearray(PREFIX)
    bad[position] ^= 1
    connection, counted = Connection(bytes(bad)), []
    with pytest.raises(ValueError, match="client_hello"):
        fixture.serve(connection, case="tls-cert-malformed", deadline=time.monotonic() + 5,
                      context=None, on_request=lambda: counted.append(1))
    assert counted == [] and connection.sent == b"" and connection.source.tell() == 0


@pytest.mark.parametrize("prefix", (b"", bytearray(PREFIX), PREFIX + b"x", PREFIX[:-1],
    b"\x16\x03\x01\x10\x00\x01\x00\x0f\xfc",
    b"\x16\x03\x01\x00\x2c\x01\x00\x00\x28"))
def test_prefix_type_size_and_declared_record_bounds(prefix):
    with pytest.raises(ValueError, match="client_hello"):
        fixture.validate_client_hello_prefix(prefix)


def test_accepted_prefix_only_is_explicitly_not_a_full_request():
    assert fixture.validate_client_hello_prefix(PREFIX) == PREFIX
    connection, counted = Connection(PREFIX), []
    fixture.serve(connection, case="tls-cert-malformed", deadline=time.monotonic() + 5,
                  context=None, on_request=lambda: counted.append(1))
    assert counted == [1] and connection.sent == public.TLS_MALFORMED_BYTES
    assert connection.source.tell() == 0


@pytest.mark.parametrize("length", range(9))
def test_truncated_prefix_cannot_count_and_waits_only_until_deadline(length, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(fixture.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(fixture.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    connection, counted = Connection(PREFIX[:length]), []
    with pytest.raises(ValueError, match="deadline|client_hello_eof"):
        fixture.serve(connection, case="tls-cert-malformed", deadline=100.03,
                      context=None, on_request=lambda: counted.append(1))
    assert counted == [] and connection.sent == b"" and len(connection.peeks) <= 7


def test_fragmented_prefix_retains_all_bytes(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(fixture.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(fixture.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    class Fragmented(Connection):
        available = 0
        def recv(self, count, flags=0):
            self.available += 1
            return super().recv(min(count, self.available), flags)
    connection, counted = Fragmented(PREFIX + b"retained"), []
    fixture.serve(connection, case="tls-cert-malformed", deadline=101,
                  context=None, on_request=lambda: counted.append(1))
    assert counted == [1] and connection.source.tell() == 0 and len(connection.peeks) == 9


def test_stalled_case_counts_prefix_then_only_waits_to_deadline(monkeypatch):
    now, sleeps = [100.0], []
    monkeypatch.setattr(fixture.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(fixture.time, "sleep", lambda seconds: sleeps.append(seconds))
    connection, counted = Connection(PREFIX), []
    fixture.serve(connection, case="tls-cert-stalled", deadline=101,
                  context=None, on_request=lambda: counted.append(1))
    assert counted == [1] and sleeps == [1] and connection.sent == b""


@pytest.mark.parametrize("deadline", (0, float("inf"), float("nan")))
def test_invalid_deadline_cannot_touch_connection_or_count(deadline):
    connection, counted = Connection(PREFIX), []
    with pytest.raises(ValueError, match="deadline"):
        fixture.serve(connection, case="tls-cert-ok", deadline=deadline,
                      context=None, on_request=lambda: counted.append(1))
    assert counted == [] and connection.peeks == []


@pytest.mark.parametrize("case", (None, True, "openssl-ok", "tls-cert-unknown"))
def test_unknown_case_cannot_touch_connection(case):
    connection = Connection(PREFIX)
    with pytest.raises(ValueError, match="material_case"):
        fixture.serve(connection, case=case, deadline=time.monotonic() + 5,
                      context=None, on_request=lambda: pytest.fail("unexpected count"))
    assert connection.peeks == []


def test_material_hash_failure_precedes_loading_any_owner_key(monkeypatch):
    monkeypatch.setitem(material.CERTIFICATES, "tls-cert-ok", b"changed certificate")
    with pytest.raises(ValueError, match="material_mismatch"):
        fixture.tls_context("tls-cert-ok")


def test_standalone_owner_import_works_without_site_or_package_path():
    code = "import importlib.util; s=importlib.util.spec_from_file_location('owner',%r); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); assert len(m.fixture.TLS_CERTIFICATE_CASES)==12" % fixture.__file__
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code], capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr.decode()
