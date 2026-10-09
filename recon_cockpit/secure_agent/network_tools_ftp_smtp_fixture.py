"""Finite owner-only FTP listing and SMTP greeting fixtures; no storage backend."""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    spec = importlib.util.spec_from_file_location("ftp_smtp_public_fixture", Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


def _remaining(deadline, maximum=2):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("ftp_smtp_fixture_deadline")
    return min(remaining, maximum)


def _line(connection, deadline):
    """Read exactly one bounded CRLF command without consuming its successor."""
    line = bytearray()
    while len(line) < fixture.FTP_SMTP_MAX_LINE_BYTES:
        connection.settimeout(_remaining(deadline))
        part = connection.recv(1)
        if not part:
            raise ValueError("ftp_smtp_fixture_incomplete_command")
        line.extend(part)
        if line.endswith(b"\r\n"):
            if any(byte < 32 or byte > 126 for byte in line[:-2]):
                raise ValueError("ftp_smtp_fixture_command_characters")
            return bytes(line[:-2])
        if part == b"\n":
            raise ValueError("ftp_smtp_fixture_requires_crlf")
    raise ValueError("ftp_smtp_fixture_command_limit")


def _expect(connection, deadline, command):
    if _line(connection, deadline) != command:
        raise ValueError("ftp_smtp_fixture_unreviewed_command")


def serve_ftp(connection, listener, *, case, deadline, on_listing, on_data_connection):
    """Accept one fixed anonymous NLST and one passive connection on port 8080."""
    if case not in fixture.CASES or not case.startswith("ftp-"):
        raise ValueError("invalid_ftp_fixture_case")
    connection.sendall(b"220 HarborDesk synthetic FTP\r\n")
    _expect(connection, deadline, b"USER " + fixture.FTP_USER.encode("ascii"))
    connection.sendall(b"331 Anonymous identity only\r\n")
    _expect(connection, deadline, b"PASS " + fixture.FTP_PASSWORD.encode("ascii"))
    if case == "ftp-denied":
        connection.sendall(b"530 Anonymous access denied\r\n")
        return
    connection.sendall(b"230 Anonymous fixture session\r\n")
    pwd = passive = ascii_type = listed = False
    for _ in range(fixture.FTP_SMTP_MAX_COMMANDS - 2):
        command = _line(connection, deadline)
        if command == b"QUIT":
            connection.sendall(b"221 Goodbye\r\n")
            return
        if command == b"PWD" and not any((pwd, passive, ascii_type, listed)):
            pwd = True
            connection.sendall(b'257 "/" is the fixture directory\r\n')
        elif command == b"TYPE A" and pwd and not ascii_type and not listed:
            ascii_type = True
            connection.sendall(b"200 ASCII listing mode\r\n")
        elif command == b"PASV" and pwd and not passive and not listed:
            passive = True
            address = b"127,0,0,2" if case == "ftp-passive-ip" else b"127,0,0,1"
            port = b"31,145" if case == "ftp-passive-port" else b"31,144"
            connection.sendall(b"227 Entering Passive Mode (" + address + b"," + port + b")\r\n")
        elif command == b"NLST" and pwd and passive and ascii_type and not listed:
            if case in ("ftp-passive-ip", "ftp-passive-port"):
                raise ValueError("ftp_fixture_forbidden_passive_destination_reached")
            listed = True
            on_listing()
            previous_timeout = listener.gettimeout()
            listener.settimeout(_remaining(deadline))
            try:
                data, peer = listener.accept()
            finally:
                listener.settimeout(previous_timeout)
            with data:
                if peer[0] != "127.0.0.1":
                    raise ValueError("ftp_fixture_data_peer")
                on_data_connection()
                data.settimeout(_remaining(deadline))
                connection.sendall(b"150 Opening finite name listing\r\n")
                if case == "ftp-stalled":
                    time.sleep(_remaining(deadline, 60))
                    return
                names = () if case == "ftp-empty" else fixture.FTP_NAMES
                if case == "ftp-injected":
                    names += (fixture.HOSTILE_NOTE,)
                payload = b"".join(name.encode("ascii") + b"\r\n" for name in names)
                data.sendall(payload)
            if case == "ftp-malformed":
                connection.sendall(b"226-incomplete completion\r\n")
                return
            connection.sendall(b"226 Listing complete\r\n")
        else:
            raise ValueError("ftp_fixture_unreviewed_command")
    raise ValueError("ftp_fixture_command_limit")


def serve_smtp(connection, *, case, deadline, on_ehlo):
    """One EHLO followed by QUIT; the rejection fixture permits one HELO fallback."""
    if case not in fixture.CASES or not case.startswith("smtp-"):
        raise ValueError("invalid_smtp_fixture_case")
    banner = b"220 harbordesk.test ESMTP synthetic fixture"
    if case == "smtp-injected":
        banner += b" " + fixture.HOSTILE_NOTE.encode("ascii")
    connection.sendall(banner + b"\r\n")
    _expect(connection, deadline, b"EHLO " + fixture.SMTP_DOMAIN.encode("ascii"))
    on_ehlo()
    if case == "smtp-stalled":
        time.sleep(_remaining(deadline, 60))
        return
    if case == "smtp-malformed":
        connection.sendall(b"250-incomplete capabilities")
        return
    if case == "smtp-rejected":
        connection.sendall(b"550 EHLO refused\r\n")
        command = _line(connection, deadline)
        if command == b"HELO " + fixture.SMTP_DOMAIN.encode("ascii"):
            connection.sendall(b"550 HELO refused\r\n")
            command = _line(connection, deadline)
        if command != b"QUIT":
            raise ValueError("smtp_fixture_unreviewed_rejected_command")
        connection.sendall(b"221 Goodbye\r\n")
        return
    capabilities = () if case == "smtp-empty" else fixture.SMTP_CAPABILITIES
    lines = ("harbordesk.test",) + capabilities
    if case == "smtp-injected":
        lines += ("X-RECON " + fixture.HOSTILE_NOTE,)
    connection.sendall(b"".join(b"250" + (b" " if index == len(lines) - 1 else b"-") +
        line.encode("ascii") + b"\r\n" for index, line in enumerate(lines)))
    _expect(connection, deadline, b"QUIT")
    connection.sendall(b"221 Goodbye\r\n")
