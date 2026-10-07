"""Owned fixed LDAP StartTLS and clean TLS close, without bind or application data."""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    spec = importlib.util.spec_from_file_location("ldap_tls_public_fixture",
        Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("ldap_tls_fixture_deadline")
    return remaining


def _read_request(connection, deadline):
    # Neither client lengths nor untrusted BER fields control parsing or
    # allocation. Only the reviewed message-ID-1 StartTLS request is accepted.
    for value in fixture.LDAP_TLS_REQUEST:
        connection.settimeout(min(2, _remaining(deadline)))
        if connection.recv(1) != bytes([value]):
            raise ValueError("ldap_tls_fixture_fixed_request_only")


def _send(connection, raw, deadline):
    connection.settimeout(min(2, _remaining(deadline)))
    connection.sendall(raw)


def serve(connection, *, case, deadline, context, on_request):
    response = fixture.ldap_tls_response(case)
    _read_request(connection, deadline)
    complete = case in fixture.LDAP_TLS_COMPLETE_CASES
    if not complete:
        # Negative counters prove the exact client StartTLS operation reached
        # the owned endpoint. They never attest a completed TLS handshake.
        on_request()
    if response is None:
        time.sleep(_remaining(deadline))
        return
    if len(response) > fixture.LDAP_TLS_MAX_RESPONSE_BYTES:
        raise ValueError("ldap_tls_fixture_response_limit")
    if case == "ldap-tls-fragmented":
        # The reviewed native LDAP prelude reader performs one BIO_read.
        # Fragmentation is a negative compatibility case, not a TLS success.
        _send(connection, response[:1], deadline)
        time.sleep(min(0.2, _remaining(deadline)))
        _send(connection, response[1:], deadline)
        return
    _send(connection, response, deadline)
    if case in ("ldap-tls-refused", "ldap-tls-referral", "ldap-tls-malformed", "ldap-tls-truncated"):
        return
    if case == "ldap-tls-bad-tls":
        _send(connection, fixture.TLS_MALFORMED_BYTES, deadline)
        return
    connection.settimeout(min(2, _remaining(deadline)))
    secured = context.wrap_socket(connection, server_side=True, suppress_ragged_eofs=False)
    try:
        if secured.version() != "TLSv1.3":
            raise ValueError("ldap_tls_fixture_version")
        secured.settimeout(min(2, _remaining(deadline)))
        # unwrap requires close_notify and rejects post-TLS Bind, Search,
        # credentials or any other LDAP/application bytes before completion.
        closed = secured.unwrap()
        try:
            if complete:
                on_request()
        finally:
            closed.close()
    finally:
        secured.close()
