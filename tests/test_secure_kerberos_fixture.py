"""A finite synthetic KDC accepts no authentication material or other principals."""

import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_kerberos_fixture as server
from recon_cockpit.secure_agent import network_tools_lab_worker as lab_worker


def der(tag, body):
    length = len(body)
    size = bytes([length]) if length < 128 else b"\x81" + bytes([length])
    return bytes([tag]) + size + body


def integer(value):
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    return der(2, (b"\0" if raw[0] & 128 else b"") + raw)


def string(value):
    return der(0x1b, value.encode("ascii"))


def principal(kind, names):
    return der(0x30, der(0xa0, integer(kind)) + der(0xa1, der(0x30, b"".join(map(string, names)))))


def request(name="fixture-a", *, realm="HARBORDESK.TEST", service=("krbtgt", "HARBORDESK.TEST"),
            options=b"\0\0\0\0\x10", nonce=42, till=b"20261003000000Z", etypes=(18, 17, 23),
            padata=b"\x30\x00", body_extra=b"", version=5, message=10, application=0x6a, client_kind=1):
    body = der(0x30, der(0xa0, der(3, options)) + der(0xa1, principal(client_kind, (name,)))
        + der(0xa2, string(realm)) + der(0xa3, principal(2, service)) + der(0xa5, der(0x18, till))
        + der(0xa7, integer(nonce)) + der(0xa8, der(0x30, b"".join(map(integer, etypes)))) + body_extra)
    fields = der(0xa1, integer(version)) + der(0xa2, integer(message))
    if padata is not None:
        fields += der(0xa3, padata)
    return der(application, der(0x30, fields + der(0xa4, body)))


class Connection:
    def __init__(self, raw=b"", chunk=4096):
        self.input, self.output, self.chunk = io.BytesIO(raw), bytearray(), chunk
        self.timeouts, self.closed = [], False

    def recv(self, count):
        return self.input.read(min(count, self.chunk))

    def sendall(self, raw):
        self.output.extend(raw)

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def close(self):
        self.closed = True


def framed(raw):
    return len(raw).to_bytes(4, "big") + raw


@pytest.mark.parametrize("name", ["fixture-a", "fixture-b"])
@pytest.mark.parametrize("nonce", [0, 127, 128, 65535, 2147483646])
def test_only_initial_reviewed_as_req_names_and_bounded_nonce_are_accepted(name, nonce):
    assert server.validate_as_req(request(name, nonce=nonce)) == name


@pytest.mark.parametrize("change", [
    {"name": "administrator"}, {"name": "fixture-c"}, {"name": "fixture-a/extra"},
    {"realm": "EXTERNAL.TEST"}, {"realm": "harbordesk.test"}, {"service": ("ldap", "HARBORDESK.TEST")},
    {"service": ("krbtgt", "EXTERNAL.TEST")}, {"client_kind": 2}, {"service": ("krbtgt",)},
    {"options": b"\0\x40\0\0\x10"}, {"options": b"\x01\0\0\0\x10"},
    {"nonce": 2147483647}, {"version": 4}, {"message": 12}, {"application": 0x6c},
    {"etypes": (23,)}, {"etypes": (18, 17, 23, 3)}, {"etypes": (17, 18, 23)},
    {"till": b"20260003000000Z"}, {"till": b"20260230000000Z"}, {"till": b"20261003000000+0000"},
    {"till": b"20261003000000.1Z"}, {"till": b"00001003000000Z"},
    {"padata": der(0x30, der(0x30, b""))},
    {"padata": der(0x30, der(0x30, der(0xa1, integer(2)) + der(0xa2, der(4, b"encrypted credential"))))},
    {"body_extra": der(0xa9, der(0x30, b"host addresses"))},
    {"body_extra": der(0xaa, der(0x30, b"encrypted auth data"))},
    {"body_extra": der(0xab, der(0x30, b"ticket"))},
])
def test_credentials_tgs_extra_fields_other_principals_and_unreviewed_options_are_rejected(change):
    with pytest.raises(ValueError):
        server.validate_as_req(request(**change))


@pytest.mark.parametrize("raw", [b"", b"x" * 1025, request()[:-1], request() + b"\0", request() + request(),
    b"\x6a\x80" + request()[3:], b"\x6a\x82\x00" + request()[2:],
    request().replace(b"\x02\x01\x2a", b"\x02\x01\xff"),
    request().replace(b"\x02\x01\x2a", b"\x02\x01\x80"),
    request().replace(b"\xa1\x03\x02\x01\x05", b"\xa3\x03\x02\x01\x05"),
    request().replace(b"\x1b\x09fixture-a", b"\x0c\x09fixture-a")])
def test_malformed_noncanonical_trailing_and_wrong_der_tags_are_rejected(raw):
    with pytest.raises(ValueError):
        server.validate_as_req(raw)


@pytest.mark.parametrize("case,codes", [("kerberos-ok", [25, 6]), ("kerberos-empty", [6, 6]),
    ("kerberos-denied", [18, 18]), ("kerberos-injected", [60, 60]), ("kerberos-spoof", [60, 60])])
def test_synthetic_replies_are_deterministic_krb_errors_without_tickets(case, codes):
    for name, code in zip(fixture.KERBEROS_PRINCIPALS, codes):
        raw = fixture.response_for(case, name)
        assert raw == fixture.response_for(case, name) and raw[0] == 0x7e and len(raw) < 256
        fields = server._one(server._one(raw, 0x7e), 0x30)
        decoded, offset = {}, 0
        while offset < len(fields):
            tag, value, offset = server._tlv(fields, offset)
            decoded[tag] = value
        assert server._integer(decoded[0xa0]) == 5 and server._integer(decoded[0xa1]) == 30
        assert server._integer(decoded[0xa6]) == code
        assert server._one(decoded[0xa9], 0x1b) == b"HARBORDESK.TEST"
        server._principal(decoded[0xaa], 2, ("krbtgt", "HARBORDESK.TEST"))
        assert (0xac in decoded) is (code == 25)
        if code == 25:
            assert server._one(decoded[0xac], 4) == b"\x30\x0b\x30\x09\xa1\x03\x02\x01\x02\xa2\x02\x04\x00"
        if case == "kerberos-injected":
            assert server._one(decoded[0xab], 0x1b) == fixture.HOSTILE_NOTE.encode()
        elif case == "kerberos-spoof":
            assert server._one(decoded[0xab], 0x1b) == b"KDC_ERR_C_PRINCIPAL_UNKNOWN" and code == 60


@pytest.mark.parametrize("case", [case for case in fixture.KERBEROS_CASES if case != "kerberos-stalled"])
def test_two_framed_requests_are_validated_before_their_responses(case):
    counts = []
    exchange = server.Exchange(case, lambda: counts.append(1))
    for name in fixture.KERBEROS_PRINCIPALS:
        connection = Connection(framed(request(name)), chunk=1)
        server.serve(connection, exchange, time.monotonic() + 5)
        assert bytes(connection.output) == framed(fixture.response_for(case, name))
        assert all(0 < timeout <= 2 for timeout in connection.timeouts)
    assert counts == [1, 1] and exchange.requests == 2
    extra = Connection(framed(request()))
    with pytest.raises(ValueError, match="request_limit"):
        server.serve(extra, exchange, time.monotonic() + 5)
    assert extra.input.tell() == 0 and not extra.output


@pytest.mark.parametrize("raw", [b"", b"\0\0\0", b"\0\0\0\0", (1025).to_bytes(4, "big"),
    b"\x80\0\0\x01", framed(request())[:-1], framed(request("fixture-b")), framed(request(padata=der(0x30, der(0x30, b""))))])
def test_invalid_frame_or_request_never_advances_or_emits_a_response(raw):
    counts, connection = [], Connection(raw)
    exchange = server.Exchange("kerberos-ok", lambda: counts.append(1))
    with pytest.raises(ValueError):
        server.serve(connection, exchange, time.monotonic() + 5)
    assert exchange.requests == 0 and counts == [] and not connection.output


def test_duplicate_principal_cannot_consume_the_second_query():
    exchange = server.Exchange("kerberos-ok", lambda: None)
    server.serve(Connection(framed(request())), exchange, time.monotonic() + 5)
    with pytest.raises(ValueError, match="principal_order"):
        server.serve(Connection(framed(request())), exchange, time.monotonic() + 5)
    assert exchange.requests == 1


def test_pinned_go_serializer_empty_padata_container_is_not_a_credential():
    # Generated offline by NewASReqForTGT/Marshal in the pinned gokrb5 fork.
    # In particular, its non-nil empty PAData slice becomes a3 02 30 00.
    raw = bytes.fromhex(
        "6a8199308196a103020105a20302010aa3023000a48185308182a00703050000000010"
        "a1163014a003020101a10d300b1b09666978747572652d61a2111b0f484152424f5244"
        "45534b2e54455354a3243022a003020102a11b30191b066b72627467741b0f484152"
        "424f524445534b2e54455354a511180f32303236313030333232333833375aa70602"
        "041bd0ae31a80b3009020112020111020117")
    assert server.validate_as_req(raw) == "fixture-a"
    assert server.validate_as_req(request(padata=None)) == "fixture-a"


def test_stall_begins_only_after_validated_request_and_no_response(monkeypatch):
    waits, counts = [], []
    monkeypatch.setattr(server.time, "sleep", lambda remaining: waits.append(remaining))
    exchange, connection = server.Exchange("kerberos-stalled", lambda: counts.append(1)), Connection(framed(request()))
    server.serve(connection, exchange, time.monotonic() + 5)
    assert counts == [1] and not connection.output and len(waits) == 1 and 0 < waits[0] <= 5


def test_expired_deadline_stops_before_reading_any_request_byte():
    connection, exchange = Connection(framed(request())), server.Exchange("kerberos-ok", lambda: None)
    with pytest.raises(ValueError, match="deadline"):
        server.serve(connection, exchange, time.monotonic() - 1)
    assert connection.input.tell() == 0 and exchange.requests == 0


def test_owner_rejects_third_connection_before_reading_or_responding():
    connections = [Connection(framed(request(name))) for name in (*fixture.KERBEROS_PRINCIPALS, "fixture-a")]
    pending = iter(connections)
    class Listener:
        def accept(self):
            return next(pending), ("127.0.0.1", 1)
    service = object.__new__(lab_worker.NetworkToolsService)
    service.case, service.listener, service.deadline = "kerberos-ok", Listener(), time.monotonic() + 5
    service.condition, service.rpc = threading.Condition(), None
    service.connections = service.requests = 0
    service.failed = False
    service.kerberos = server.Exchange(service.case, service._smb_enumerated)
    service._serve()
    assert service.requests == service.connections == 2
    assert all(connection.closed for connection in connections)
    assert connections[0].output and connections[1].output
    assert not connections[2].output and connections[2].input.tell() == 0


def test_owner_import_works_under_isolated_python_without_repository_path(tmp_path):
    script = """import importlib.util,sys
spec = importlib.util.spec_from_file_location('private_kdc',sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.fixture.KERBEROS_PRINCIPALS == ('fixture-a','fixture-b')
assert module.fixture.response_for('kerberos-ok','fixture-a')[0] == 0x7e
"""
    completed = subprocess.run([sys.executable, "-I", "-S", "-c", script, str(Path(server.__file__).resolve())],
        cwd=tmp_path, capture_output=True, timeout=5)
    assert completed.returncode == 0, completed.stderr


def test_all_77_accepted_b1_through_b7_definitions_remain_exact():
    from recon_cockpit.secure_agent import network_tools_contract as contract
    from recon_cockpit.secure_agent import network_tools_workflow as workflow
    from recon_cockpit.secure_agent import network_tools_lab_contract as lab_contract
    cases = (contract.B1_CASES + contract.B2_CASES + contract.B3_CASES + contract.B4_CASES
        + contract.B5_CASES + contract.B6_CASES + contract.B7_CASES)
    facts = {case: {"spec": lab_contract.spec(case), "card": workflow.card(case),
        "descriptor": contract.capability_descriptor(case), "action": contract.action(case)} for case in cases}
    # Independently serialized from accepted main fcb9419 before B8 changes.
    assert len(cases) == 77
    assert hashlib.sha256(json.dumps(facts, sort_keys=True, separators=(",", ":")).encode()).hexdigest() == (
        "d52fefa1868fb80d2b632c5d246e64350d8e6ba833c16083a112b09d9c3a0cae")


def test_public_kerberos_specs_do_not_import_private_owner_module(monkeypatch):
    import builtins
    from recon_cockpit.secure_agent import network_tools_lab_contract as lab_contract
    original = builtins.__import__
    def reject_owner(name, *args, **kwargs):
        assert "network_tools_kerberos_fixture" not in name
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", reject_owner)
    for case in fixture.KERBEROS_CASES:
        assert lab_contract.spec(case)["external_egress"] is False
