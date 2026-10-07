"""Owned SMTP STARTTLS prelude and clean TLS close, without mail or authentication."""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    spec = importlib.util.spec_from_file_location("smtp_tls_public_fixture",
        Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("smtp_tls_fixture_deadline")
    return remaining


def _read_fixed(connection, expected, deadline):
    # No client-selected lengths, addresses, mailboxes or authentication data.
    for value in expected:
        connection.settimeout(min(2, _remaining(deadline)))
        if connection.recv(1) != bytes([value]):
            raise ValueError("smtp_tls_fixture_fixed_command_only")


def _send(connection, raw, deadline, *, fragmented=False):
    chunks = (bytes([value]) for value in raw) if fragmented else (raw,)
    for chunk in chunks:
        connection.settimeout(min(2, _remaining(deadline)))
        connection.sendall(chunk)
        if fragmented:
            time.sleep(min(0.002, _remaining(deadline)))


def serve(connection, *, case, deadline, context, on_request):
    dialogue = fixture.smtp_tls_dialogue(case)
    fragmented = case == "smtp-tls-fragmented"
    _send(connection, dialogue["banner"], deadline, fragmented=fragmented)
    _read_fixed(connection, fixture.SMTP_TLS_EHLO, deadline)
    _send(connection, dialogue["ehlo"], deadline, fragmented=fragmented)
    _read_fixed(connection, fixture.SMTP_TLS_STARTTLS, deadline)
    complete = case in fixture.SMTP_TLS_COMPLETE_CASES
    if not complete:
        # Negative scenarios prove execution reached both exact commands.
        # This is not a TLS-handshake completion witness.
        on_request()
    if case == "smtp-tls-stalled":
        time.sleep(_remaining(deadline))
        return
    if dialogue["ready"] is not None:
        # OpenSSL reads this transition once. Fragmentation applies only to
        # the banner/EHLO lines, which it consumes with its line reader.
        _send(connection, dialogue["ready"], deadline)
    if case in ("smtp-tls-refused", "smtp-tls-ehlo-refused", "smtp-tls-truncated"):
        return
    if case == "smtp-tls-malformed":
        _send(connection, fixture.TLS_MALFORMED_BYTES, deadline)
        return
    connection.settimeout(min(2, _remaining(deadline)))
    secured = context.wrap_socket(connection, server_side=True, suppress_ragged_eofs=False)
    try:
        if secured.version() != "TLSv1.3":
            raise ValueError("smtp_tls_fixture_version")
        secured.settimeout(min(2, _remaining(deadline)))
        # close_notify is required. Any post-TLS EHLO, AUTH, MAIL, RCPT or
        # message bytes cause unwrap to fail and cannot count as completion.
        closed = secured.unwrap()
        try:
            if complete:
                on_request()
        finally:
            closed.close()
    finally:
        secured.close()
