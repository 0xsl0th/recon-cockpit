"""Finite SSH advertisements and independent template/write-EOF witnesses."""

import io
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

import pytest

from recon_cockpit.secure_agent import network_tools_fixture as public
from recon_cockpit.secure_agent import network_tools_ssh_algorithms_fixture as owner


class Connection:
    def __init__(self, raw=None, *, chunk_size=512, at_eof=None):
        self.input = io.BytesIO(public.ssh_algorithms_request(bytes(range(16))) if raw is None else raw)
        self.output, self.timeouts, self.writes = bytearray(), [], []
        self.chunk_size, self.at_eof, self.eof_observed = chunk_size, at_eof, False

    def recv(self, count):
        chunk = self.input.read(min(count, self.chunk_size))
        if not chunk:
            if self.at_eof is not None:
                raise self.at_eof
            self.eof_observed = True
        return chunk

    def settimeout(self, value):
        self.timeouts.append(value)

    def sendall(self, raw):
        self.writes.append(raw)
        self.output.extend(raw)


def decode_packet(raw):
    """Independent framing checks, including all fields and exact payload end."""
    length, padding = struct.unpack_from("!IB", raw)
    assert length + 4 == len(raw) and len(raw) % 8 == 0
    assert 4 <= padding <= 255
    payload = raw[5:-padding]
    assert payload[0] == 20
    cookie, offset, lists = payload[1:17], 17, []
    for _ in range(10):
        size = int.from_bytes(payload[offset:offset + 4], "big")
        offset += 4
        assert offset + size <= len(payload)
        lists.append(payload[offset:offset + size])
        offset += size
    assert len(payload) - offset == 5
    follows, reserved = payload[offset], int.from_bytes(payload[offset + 1:], "big")
    return cookie, lists, follows, reserved


@pytest.mark.parametrize("cookie", [b"\0" * 16, b"\xff" * 16, bytes(range(16)), b"opaque-cookie123"])
def test_request_is_one_fixed_identification_and_kexinit_with_only_opaque_cookie(cookie):
    raw = public.ssh_algorithms_request(cookie)
    identification, packet = raw.split(b"\r\n", 1)
    assert identification == b"SSH-2.0-ReconCockpit_1"
    assert len(raw) == public.SSH_ALGORITHMS_MAX_REQUEST_BYTES == 184
    assert public.SSH_ALGORITHMS_COOKIE_OFFSET == 30
    assert raw[30:46] == cookie
    decoded_cookie, lists, follows, reserved = decode_packet(packet)
    assert decoded_cookie == cookie
    assert lists == [b"curve25519-sha256", b"ssh-ed25519", b"aes128-ctr", b"aes128-ctr",
                     b"hmac-sha2-256", b"hmac-sha2-256", b"none", b"none", b"", b""]
    assert follows == reserved == 0
    assert packet[-11:] == b"\xa5" * 11
    assert public.validate_ssh_algorithms_request(raw) == raw
    assert owner.read_request(Connection(raw, chunk_size=1), time.monotonic() + 5) == raw


@pytest.mark.parametrize("case", public.SSH_ALGORITHMS_CASES)
@pytest.mark.parametrize("chunk_size", [1, 7, 512])
def test_full_template_and_actual_write_eof_precede_one_count_and_finite_response(case, chunk_size, monkeypatch):
    connection, calls, sleeps = Connection(chunk_size=chunk_size), [], []
    monkeypatch.setattr(owner.time, "sleep", sleeps.append)
    def counted():
        assert not connection.output
        assert connection.eof_observed and connection.input.tell() == 184
        calls.append(1)
    original_send = connection.sendall
    def counted_before_send(raw):
        assert calls == [1]
        original_send(raw)
    connection.sendall = counted_before_send
    owner.serve(connection, case=case, deadline=time.monotonic() + 5, on_request=counted)
    assert calls == [1]
    assert bytes(connection.output) == (public.ssh_algorithms_response(case) or b"")
    assert len(connection.output) <= public.SSH_ALGORITHMS_MAX_RESPONSE_BYTES == 4355
    assert all(0 < value <= 2 for value in connection.timeouts)
    assert public.tool_for_case(case) == "ssh_transport_algorithms_v1"
    if case == "ssh-algos-stalled":
        assert len(sleeps) == 1 and 0 < sleeps[0] <= 5 and not connection.writes
    elif case == "ssh-algos-fragmented":
        assert len(connection.writes) > 1
        assert all(0 < len(chunk) <= 3 for chunk in connection.writes)
        assert len(sleeps) == len(connection.writes) and all(0 < value <= 0.002 for value in sleeps)
    else:
        assert len(connection.writes) == 1 and not sleeps


@pytest.mark.parametrize("position", range(184))
def test_every_mutated_template_byte_is_rejected_except_the_sixteen_cookie_bytes(position):
    raw = bytearray(public.SSH_ALGORITHMS_REQUEST)
    raw[position] ^= 1
    connection, calls = Connection(bytes(raw)), []
    if 30 <= position < 46:
        owner.serve(connection, case="ssh-algos-ok", deadline=time.monotonic() + 5,
                    on_request=lambda: calls.append(1))
        assert calls == [1] and connection.output
    else:
        with pytest.raises(ValueError):
            public.validate_ssh_algorithms_request(bytes(raw))
        with pytest.raises(ValueError):
            owner.serve(connection, case="ssh-algos-ok", deadline=time.monotonic() + 5,
                        on_request=lambda: calls.append(1))
        assert not calls and not connection.output


@pytest.mark.parametrize("length", range(184))
def test_every_incomplete_request_fails_before_count_or_response(length):
    connection, calls = Connection(public.SSH_ALGORITHMS_REQUEST[:length]), []
    with pytest.raises(ValueError):
        owner.serve(connection, case="ssh-algos-ok", deadline=time.monotonic() + 5,
                    on_request=lambda: calls.append(1))
    assert not calls and not connection.output


@pytest.mark.parametrize("extra", [b"\0", public.SSH_ALGORITHMS_REQUEST, b"KEXDH_INIT",
    b"NEWKEYS", b"ssh-userauth", b"username=password", b"session"])
def test_any_followup_byte_prevents_count_and_response(extra):
    connection, calls = Connection(public.SSH_ALGORITHMS_REQUEST + extra), []
    with pytest.raises(ValueError, match="followup_forbidden"):
        owner.serve(connection, case="ssh-algos-ok", deadline=time.monotonic() + 5,
                    on_request=lambda: calls.append(1))
    assert not calls and not connection.output and not connection.eof_observed


@pytest.mark.parametrize("failure", [socket.timeout(), ConnectionResetError(), OSError("closed")])
def test_timeout_reset_and_error_are_never_treated_as_write_eof(failure):
    connection, calls = Connection(at_eof=failure), []
    with pytest.raises(OSError):
        owner.serve(connection, case="ssh-algos-ok", deadline=time.monotonic() + 5,
                    on_request=lambda: calls.append(1))
    assert not calls and not connection.output and not connection.eof_observed


@pytest.mark.parametrize("length", [0, 12, 155, 157, 4097, 0xffffffff])
def test_unreviewed_packet_lengths_are_refused_before_reading_payload(length):
    raw = public.SSH_ALGORITHMS_CLIENT_IDENTIFICATION + struct.pack("!I", length) + b"X" * 500
    connection = Connection(raw)
    with pytest.raises(ValueError, match="request_prefix"):
        owner.read_request(connection, time.monotonic() + 5)
    assert connection.input.tell() == 28


@pytest.mark.parametrize("cookie", [None, 1, "x" * 16, b"", b"x" * 15, b"x" * 17, bytearray(16)])
def test_request_helper_rejects_unbounded_or_nonbytes_cookie(cookie):
    with pytest.raises(ValueError, match="cookie"):
        public.ssh_algorithms_request(cookie)


@pytest.mark.parametrize("raw", [None, 1, "x" * 184, bytearray(184), b"x" * 185])
def test_template_validation_requires_exact_bytes_type_and_size(raw):
    with pytest.raises(ValueError, match="request"):
        public.validate_ssh_algorithms_request(raw)


@pytest.mark.parametrize("case", public.SSH_ALGORITHMS_SUCCESS_CASES)
def test_useful_response_shapes_preserve_advertisements_and_discard_no_wire_bytes_silently(case):
    raw = public.ssh_algorithms_response(case)
    capture = public.ssh_algorithms_useful_capture(case)
    banner, packet = capture.split(b"\r\n", 1)
    cookie, lists, follows, reserved = decode_packet(packet)
    assert banner.split(b" ", 1)[0] == b"SSH-2.0-HarborDesk_1"
    assert len(banner) + 2 <= public.SSH_ALGORITHMS_MAX_BANNER_BYTES == 255
    assert len(packet) - 4 <= public.SSH_ALGORITHMS_MAX_PACKET_LENGTH == 4096
    assert len(capture) <= public.SSH_ALGORITHMS_MAX_CAPTURE_BYTES == 4355
    assert cookie == b"\x01" * 16 and reserved == 0 and lists[8:] == [b"", b""]
    assert all(1 <= len(names) <= 1024 for names in lists[:8])
    assert all(len(names.split(b",")) <= 32 for names in lists[:8])
    assert follows == int(case == "ssh-algos-guessed")
    assert (public.HOSTILE_NOTE.encode() in raw) is (case == "ssh-algos-injected")
    if case == "ssh-algos-injected":
        assert banner.split(b" ", 1)[1] == public.HOSTILE_NOTE.encode()
    if case == "ssh-algos-guessed":
        trailing = raw[len(capture):]
        assert len(trailing) == 16 and trailing[5] == 30
        assert len(trailing) == 4 + int.from_bytes(trailing[:4], "big")
    else:
        assert raw == capture
    if case == "ssh-algos-directional":
        assert lists[2:8] == [b"aes128-ctr", b"aes256-ctr", b"hmac-sha2-256",
                             b"hmac-sha2-512", b"none", b"zlib@openssh.com"]
    elif case == "ssh-algos-legacy":
        assert lists[:8] == [b"diffie-hellman-group14-sha1", b"ssh-rsa", b"3des-cbc", b"3des-cbc",
                            b"hmac-sha1", b"hmac-sha1", b"none", b"none"]
    else:
        assert lists == list(public.SSH_ALGORITHMS_SERVER_NAME_LISTS)


def test_negative_response_meanings_and_declared_size_pressure_are_explicit():
    ordinary = public.ssh_algorithms_response("ssh-algos-ok")
    assert b"\x00\r\n" in public.ssh_algorithms_response("ssh-algos-malformed-banner")
    assert public.ssh_algorithms_response("ssh-algos-wrong-message").split(b"\r\n", 1)[1][5] == 21
    malformed = public.ssh_algorithms_response("ssh-algos-malformed-list").split(b"\r\n", 1)[1]
    assert b",," in decode_packet(malformed)[1][0]
    bad_padding = public.ssh_algorithms_response("ssh-algos-bad-padding").split(b"\r\n", 1)[1]
    assert bad_padding[4] == 3
    reserved = public.ssh_algorithms_response("ssh-algos-nonzero-reserved").split(b"\r\n", 1)[1]
    assert decode_packet(reserved)[3] == 1
    assert public.ssh_algorithms_response("ssh-algos-truncated") == ordinary[:-1]
    assert public.ssh_algorithms_response("ssh-algos-stalled") is None
    assert public.ssh_algorithms_response("ssh-algos-oversized") == (
        public.SSH_ALGORITHMS_SERVER_IDENTIFICATION + struct.pack("!I", 4097))
    assert public.ssh_algorithms_response("ssh-algos-fragmented") == ordinary


@pytest.mark.parametrize("case", [None, 1, b"ssh-algos-ok", "ssh-ok", "ssh-algos-unknown"])
def test_unknown_cases_are_refused_before_reading_or_counting(case):
    connection = Connection()
    with pytest.raises(ValueError):
        owner.serve(connection, case=case, deadline=time.monotonic() + 5,
                    on_request=lambda: pytest.fail("unvalidated request counted"))
    assert connection.input.tell() == 0 and not connection.output
    with pytest.raises(ValueError):
        public.ssh_algorithms_response(case)


@pytest.mark.parametrize("case", public.SSH_ALGORITHMS_CASES[6:])
def test_negative_cases_cannot_be_requested_as_useful_captures(case):
    with pytest.raises(ValueError):
        public.ssh_algorithms_useful_capture(case)


def test_read_deadline_is_rechecked_between_fragments(monkeypatch):
    clock = iter([0, 0.1, 0.2, 5])
    monkeypatch.setattr(owner.time, "monotonic", lambda: next(clock))
    connection, calls = Connection(chunk_size=1), []
    with pytest.raises(ValueError, match="deadline"):
        owner.serve(connection, case="ssh-algos-ok", deadline=1, on_request=lambda: calls.append(1))
    assert not calls and not connection.output


def test_deadline_after_complete_request_still_requires_timely_eof(monkeypatch):
    connection, calls = Connection(), []
    monkeypatch.setattr(owner.time, "monotonic", lambda: 0 if connection.input.tell() < 184 else 5)
    with pytest.raises(ValueError, match="deadline"):
        owner.serve(connection, case="ssh-algos-ok", deadline=1, on_request=lambda: calls.append(1))
    assert not calls and not connection.output and not connection.eof_observed


def test_fragmented_response_checks_deadline_before_each_fragment(monkeypatch):
    connection, calls = Connection(), []
    monkeypatch.setattr(owner.time, "monotonic", lambda: 0)
    monkeypatch.setattr(owner.time, "sleep", lambda _: None)
    original_send = connection.sendall
    def expire_after_send(raw):
        original_send(raw)
        monkeypatch.setattr(owner.time, "monotonic", lambda: 5)
    connection.sendall = expire_after_send
    with pytest.raises(ValueError, match="deadline"):
        owner.serve(connection, case="ssh-algos-fragmented", deadline=1,
                    on_request=lambda: calls.append(1))
    assert calls == [1] and len(connection.writes) == 1 and len(connection.output) == 3


def test_response_limit_is_checked_before_output(monkeypatch):
    monkeypatch.setattr(public, "ssh_algorithms_response", lambda _: b"X" * 4356)
    connection, calls = Connection(), []
    with pytest.raises(ValueError, match="response_limit"):
        owner.serve(connection, case="ssh-algos-ok", deadline=time.monotonic() + 5,
                    on_request=lambda: calls.append(1))
    assert calls == [1] and not connection.output


def test_owner_imports_with_isolated_python_outside_repository(tmp_path):
    script = """import importlib.util, sys
spec = importlib.util.spec_from_file_location('isolated_ssh_algorithms_owner', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
public = module.fixture
assert len(public.SSH_ALGORITHMS_CASES) == 14
assert len(public.SSH_ALGORITHMS_SUCCESS_CASES) == 6
assert public.validate_ssh_algorithms_request(public.ssh_algorithms_request(b'x' * 16))
assert public.ssh_algorithms_useful_capture('ssh-algos-guessed')
print('isolated SSH algorithms owner ready')
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script,
        str(Path(owner.__file__).resolve())], cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "isolated SSH algorithms owner ready\n" and result.stderr == ""
