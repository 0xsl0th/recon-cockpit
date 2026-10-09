"""Finite protocol state tests without sockets, native programs or credentials."""

import io
import time
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import network_tools_ftp_smtp_fixture as server
from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_lab_contract as contract


class Connection:
    def __init__(self, commands=b""):
        self.input = io.BytesIO(commands)
        self.output = bytearray()
        self.timeout = None
        self.closed = False

    def recv(self, count):
        return self.input.read(count)

    def sendall(self, value):
        self.output.extend(value)

    def settimeout(self, timeout):
        self.timeout = timeout

    def gettimeout(self):
        return self.timeout

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True


class Listener(Connection):
    def __init__(self):
        super().__init__()
        self.data = Connection()
        self.accepted = 0

    def accept(self):
        self.accepted += 1
        assert self.accepted == 1
        return self.data, ("127.0.0.1", 40000)


def ftp(case, commands=None):
    if commands is None:
        commands = b"USER anonymous\r\nPASS anonymous@\r\nPWD\r\nPASV\r\nTYPE A\r\nNLST\r\nQUIT\r\n"
    control, listener, counts = Connection(commands), Listener(), [0, 0]
    def listing():
        counts[0] += 1
    def data():
        counts[1] += 1
    server.serve_ftp(control, listener, case=case, deadline=time.monotonic() + 5,
                     on_listing=listing, on_data_connection=data)
    return control, listener, counts


@pytest.mark.parametrize("case", ["ftp-ok", "ftp-empty", "ftp-injected", "ftp-malformed"])
def test_ftp_permits_only_one_finite_listing_and_restores_listener(case):
    control, listener, counts = ftp(case)
    assert counts == [1, 1] and listener.accepted == 1 and listener.data.closed
    assert listener.timeout is None
    payload = bytes(listener.data.output)
    assert (payload == b"") is (case == "ftp-empty")
    assert (fixture.HOSTILE_NOTE.encode() in payload) is (case == "ftp-injected")
    assert (b"226 Listing complete\r\n" in control.output) is (case != "ftp-malformed")


@pytest.mark.parametrize("case", ["ftp-passive-ip", "ftp-passive-port"])
def test_unapproved_passive_advertisements_never_advance_listing(case):
    control, listener, counts = ftp(case, b"USER anonymous\r\nPASS anonymous@\r\nPWD\r\nPASV\r\nQUIT\r\n")
    assert counts == [0, 0] and listener.accepted == 0
    assert (b"127,0,0,2" in control.output) is (case == "ftp-passive-ip")
    assert (b"31,145" in control.output) is (case == "ftp-passive-port")
    with pytest.raises(ValueError, match="forbidden_passive_destination"):
        ftp(case)


def test_ftp_denied_never_opens_data_or_lists():
    control, listener, counts = ftp("ftp-denied", b"USER anonymous\r\nPASS anonymous@\r\n")
    assert b"530 " in control.output and counts == [0, 0] and listener.accepted == 0


@pytest.mark.parametrize("command", [b"RETR public.txt", b"STOR x", b"CWD reports", b"LIST", b"EPSV",
    b"PORT 127,0,0,2,31,144", b"AUTH TLS", b"NLST public.txt", b"TYPE I", b"SITE EXEC x"])
def test_ftp_rejects_storage_authentication_and_unreviewed_commands(command):
    with pytest.raises(ValueError, match="unreviewed_command"):
        ftp("ftp-ok", b"USER anonymous\r\nPASS anonymous@\r\nPWD\r\n" + command + b"\r\n")


@pytest.mark.parametrize("commands", [b"USER admin\r\n", b"USER anonymous\r\nPASS secret\r\n",
    b"USER anonymous\n", b"USER anon\x00ymous\r\n", b"X" * 513 + b"\r\n"])
def test_ftp_rejects_other_identity_and_bad_framing(commands):
    with pytest.raises(ValueError):
        ftp("ftp-ok", commands)


def smtp(case, commands=b"EHLO reconlab\r\nQUIT\r\n"):
    connection, counts = Connection(commands), []
    server.serve_smtp(connection, case=case, deadline=time.monotonic() + 5,
        on_ehlo=lambda: counts.append(1))
    return connection, counts


@pytest.mark.parametrize("case", ["smtp-ok", "smtp-empty", "smtp-injected", "smtp-malformed"])
def test_smtp_one_ehlo_and_quit_no_mail_commands(case):
    connection, counts = smtp(case)
    assert counts == [1]
    assert (fixture.HOSTILE_NOTE.encode() in connection.output) is (case == "smtp-injected")
    if case == "smtp-empty":
        assert connection.output == b"220 harbordesk.test ESMTP synthetic fixture\r\n250 harbordesk.test\r\n221 Goodbye\r\n"
    else:
        assert (b"250-8BITMIME\r\n" in connection.output) is (case != "smtp-malformed")


def test_smtp_rejection_allows_one_benign_helo_fallback_only():
    connection, counts = smtp("smtp-rejected", b"EHLO reconlab\r\nHELO reconlab\r\nQUIT\r\n")
    assert counts == [1] and b"550 HELO refused\r\n" in connection.output
    assert b"250" not in connection.output
    with pytest.raises(ValueError):
        smtp("smtp-rejected", b"EHLO reconlab\r\nHELO reconlab\r\nHELO reconlab\r\n")


@pytest.mark.parametrize("command", [b"AUTH PLAIN eA==", b"MAIL FROM:<x>", b"RCPT TO:<x>", b"DATA",
    b"VRFY root", b"EXPN users", b"HELP", b"STARTTLS", b"EHLO reconlab", b"HELO reconlab"])
def test_smtp_forbids_authentication_mail_probes_and_repeat_greetings(command):
    with pytest.raises(ValueError, match="unreviewed_command"):
        smtp("smtp-ok", b"EHLO reconlab\r\n" + command + b"\r\n")


@pytest.mark.parametrize("case,limit", [("ftp-ok", 2), ("smtp-ok", 1)])
def test_b5_context_closes_over_exact_connection_and_single_metadata_limits(case, limit):
    expected = contract.identity(case, str(uuid4()))
    context = {"identity": expected, "connection_count": limit, "request_count": 1}
    assert contract.validate_context(context, expected) == context
    for changes in ({"connection_count": limit + 1}, {"request_count": 2}, {"request_count": True}):
        with pytest.raises(ValueError):
            contract.validate_context({**context, **changes}, expected)


def test_new_owner_module_is_not_needed_to_build_public_lab_specs(monkeypatch):
    import builtins
    original = builtins.__import__
    def reject_owner(name, *args, **kwargs):
        assert "ftp_smtp_fixture" not in name
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", reject_owner)
    for case in fixture.CASES:
        if case.startswith(("ftp-", "smtp-")):
            assert contract.spec(case)["external_egress"] is False
