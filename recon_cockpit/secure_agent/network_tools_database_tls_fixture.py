"""Owner-only STARTTLS fixtures with no database login or application backend."""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    spec = importlib.util.spec_from_file_location("database_tls_public_fixture",
        Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("database_tls_fixture_deadline")
    return remaining


def _read_fixed(connection, expected, deadline):
    # Compare as bytes arrive: neither a client length nor caller data controls
    # allocation, protocol negotiation, database selection or authentication.
    for value in expected:
        connection.settimeout(min(2, _remaining(deadline)))
        if connection.recv(1) != bytes([value]):
            raise ValueError("database_tls_fixture_ssl_request_only")


def serve(connection, *, case, deadline, context, on_request):
    if type(case) is not str or case not in fixture.DATABASE_TLS_CASES:
        raise ValueError("invalid_database_tls_fixture_case")
    response = fixture.database_tls_server_preface(case)
    if case.startswith("postgresql-"):
        _read_fixed(connection, fixture.POSTGRESQL_SSL_REQUEST, deadline)
        if response is not None:
            connection.sendall(response)
        if case.endswith(("-refused", "-malformed", "-injected")):
            return
    else:
        connection.settimeout(min(2, _remaining(deadline)))
        connection.sendall(response)
        if case.endswith(("-refused", "-malformed")):
            return
        _read_fixed(connection, fixture.MYSQL_SSL_REQUEST, deadline)
    if case.endswith("-stalled"):
        time.sleep(_remaining(deadline))
        return
    connection.settimeout(min(2, _remaining(deadline)))
    secured = context.wrap_socket(connection, server_side=True, suppress_ragged_eofs=False)
    try:
        if secured.version() != "TLSv1.3":
            raise ValueError("database_tls_fixture_version")
        secured.settimeout(min(2, _remaining(deadline)))
        # unwrap requires close_notify and rejects application data after the
        # handshake. A TCP EOF, timeout, login attempt or SQL bytes never count.
        closed = secured.unwrap()
        try:
            on_request()
        finally:
            closed.close()
    finally:
        secured.close()
