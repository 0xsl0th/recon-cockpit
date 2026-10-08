"""Owned finite SSH advertisements after a validated template and client write EOF."""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    # The owner runs with -I -S and imports only its sealed public sibling.
    spec = importlib.util.spec_from_file_location("ssh_algorithms_public_fixture",
        Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("ssh_algorithms_fixture_deadline")
    return remaining


def _read_exact(connection, count, deadline):
    result = bytearray()
    while len(result) < count:
        connection.settimeout(min(2, _remaining(deadline)))
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise ValueError("ssh_algorithms_fixture_incomplete")
        result.extend(chunk)
    return bytes(result)


def read_request(connection, deadline):
    prefix_length = len(fixture.SSH_ALGORITHMS_CLIENT_IDENTIFICATION) + 4
    prefix = _read_exact(connection, prefix_length, deadline)
    if prefix != fixture.SSH_ALGORITHMS_REQUEST[:prefix_length]:
        raise ValueError("ssh_algorithms_fixture_request_prefix")
    request = fixture.validate_ssh_algorithms_request(prefix + _read_exact(connection,
        fixture.SSH_ALGORITHMS_MAX_REQUEST_BYTES - prefix_length, deadline))
    connection.settimeout(min(2, _remaining(deadline)))
    # The whole fixed template (except its opaque random cookie) and actual
    # EOF are required. Reset/timeout never proves this owned constraint.
    if connection.recv(1) != b"":
        raise ValueError("ssh_algorithms_fixture_followup_forbidden")
    return request


def serve(connection, *, case, deadline, on_request):
    if type(case) is not str or case not in fixture.SSH_ALGORITHMS_CASES:
        raise ValueError("invalid_ssh_algorithms_fixture_case")
    read_request(connection, deadline)
    on_request()  # Validated template plus write EOF; response usefulness is separate.
    response = fixture.ssh_algorithms_response(case)
    if response is None:
        time.sleep(_remaining(deadline))
        return
    if len(response) > fixture.SSH_ALGORITHMS_MAX_RESPONSE_BYTES:
        raise ValueError("ssh_algorithms_fixture_response_limit")
    width = 3 if case == "ssh-algos-fragmented" else len(response)
    for start in range(0, len(response), width):
        connection.settimeout(min(2, _remaining(deadline)))
        connection.sendall(response[start:start + width])
        if case == "ssh-algos-fragmented":
            time.sleep(min(0.002, _remaining(deadline)))
    # The owner closes on return. No second client packet, key exchange,
    # authentication or session is interpreted here.
