"""Owner-only banner/GET service fixture for a finite Nmap probe database."""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    spec = importlib.util.spec_from_file_location("nmap_service_public_fixture",
                                                 Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("nmap_service_fixture_deadline")
    return remaining


def _receive(connection, deadline):
    connection.settimeout(min(2, _remaining(deadline)))
    return connection.recv(1)


def serve(connection, *, case, connection_index, deadline, on_metadata):
    if (type(case) is not str or case not in fixture.NMAP_SERVICE_CASES
            or type(connection_index) is not int
            or not 1 <= connection_index <= fixture.NMAP_SERVICE_MAX_CONNECTIONS):
        raise ValueError("invalid_nmap_service_exchange")
    # Nmap's initial TCP-connect check sends no application bytes and closes.
    # That accepted connection establishes no completed metadata query.
    if connection_index == 1:
        if _receive(connection, deadline) != b"":
            raise ValueError("nmap_service_fixture_scan_must_be_empty")
        return
    if case == "nmap-service-ssh":
        if connection_index != 2:
            raise ValueError("nmap_service_fixture_repeated_banner")
        connection.settimeout(min(2, _remaining(deadline)))
        connection.sendall(fixture.NMAP_SERVICE_SSH)
        on_metadata()
        return
    request = bytearray()
    while len(request) < len(fixture.NMAP_SERVICE_GET):
        char = _receive(connection, deadline)
        if not char:
            # A NULL probe may close before the fixed GET uses a third
            # connection. Keep the service connection open while waiting so
            # the fixture itself does not trigger the tcpwrapped heuristic.
            if not request and connection_index == 2:
                return
            raise ValueError("nmap_service_fixture_incomplete_get")
        request.extend(char)
        if not fixture.NMAP_SERVICE_GET.startswith(request):
            raise ValueError("nmap_service_fixture_fixed_get_only")
    on_metadata()
    response = fixture.nmap_service_response(case)
    if response is None:
        time.sleep(_remaining(deadline))
        return
    connection.settimeout(min(2, _remaining(deadline)))
    connection.sendall(response)
