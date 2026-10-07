"""Owned FTP AUTH TLS and clean TLS close, without login or data operations."""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    spec = importlib.util.spec_from_file_location("ftp_tls_public_fixture",
        Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("ftp_tls_fixture_deadline")
    return remaining


def _read_auth(connection, deadline):
    # Only the reviewed ten bytes are accepted, without a general FTP parser.
    for value in fixture.FTP_TLS_AUTH:
        connection.settimeout(min(2, _remaining(deadline)))
        if connection.recv(1) != bytes([value]):
            raise ValueError("ftp_tls_fixture_fixed_command_only")


def _send(connection, raw, deadline, *, fragmented=False):
    chunks = (bytes([value]) for value in raw) if fragmented else (raw,)
    for chunk in chunks:
        connection.settimeout(min(2, _remaining(deadline)))
        connection.sendall(chunk)
        if fragmented:
            time.sleep(min(0.002, _remaining(deadline)))


def serve(connection, *, case, deadline, context, on_request):
    dialogue = fixture.ftp_tls_dialogue(case)
    _send(connection, dialogue["greeting"], deadline, fragmented=case == "ftp-tls-fragmented")
    _read_auth(connection, deadline)
    complete = case in fixture.FTP_TLS_COMPLETE_CASES
    if not complete:
        # These counters witness only the exact AUTH TLS request, before the
        # negative response, failed TLS handshake or stall.
        on_request()
    if dialogue["ready"] is None:
        time.sleep(_remaining(deadline))
        return
    # The native client reads this transition once without validating status.
    # Fragmentation applies only to the greeting consumed by its line reader.
    _send(connection, dialogue["ready"], deadline)
    if case == "ftp-tls-refused":
        return
    if case == "ftp-tls-malformed":
        _send(connection, fixture.TLS_MALFORMED_BYTES, deadline)
        return
    connection.settimeout(min(2, _remaining(deadline)))
    secured = context.wrap_socket(connection, server_side=True, suppress_ragged_eofs=False)
    try:
        if secured.version() != "TLSv1.3":
            raise ValueError("ftp_tls_fixture_version")
        secured.settimeout(min(2, _remaining(deadline)))
        # unwrap requires close_notify. USER/PASS, PBSZ/PROT, data commands,
        # listing, transfer or any other application bytes prevent completion.
        closed = secured.unwrap()
        try:
            if complete:
                on_request()
        finally:
            closed.close()
    finally:
        secured.close()
