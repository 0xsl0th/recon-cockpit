"""Owner-only finite SMB2 negotiation replies; no session setup, authentication or shares."""

import importlib.util
from pathlib import Path
import time

if __package__:
    from . import network_tools_fixture as fixture
else:
    spec = importlib.util.spec_from_file_location("smb2_public_fixture",
        Path(__file__).with_name("network_tools_fixture.py"))
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("smb2_fixture_deadline")
    return remaining


def _read_exact(connection, count, deadline):
    result = bytearray()
    while len(result) < count:
        connection.settimeout(min(2, _remaining(deadline)))
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise ValueError("smb2_fixture_incomplete")
        result.extend(chunk)
    return bytes(result)


def read_request(connection, deadline):
    header = _read_exact(connection, 4, deadline)
    if header != fixture.SMB2_REQUEST[:4]:
        raise ValueError("smb2_fixture_frame_limit")
    request = fixture.validate_smb2_request(header + _read_exact(connection, 104, deadline))
    connection.settimeout(min(2, _remaining(deadline)))
    # This owned profile requires a write-half-close before its reply. EOF
    # proves no SESSION_SETUP, credentials or other client bytes can follow.
    # A reset or a timeout does not satisfy this constraint.
    if connection.recv(1) != b"":
        raise ValueError("smb2_fixture_followup_forbidden")
    return request


def serve(connection, *, case, deadline, on_request):
    if type(case) is not str or case not in fixture.SMB2_CASES:
        raise ValueError("invalid_smb2_fixture_case")
    read_request(connection, deadline)
    on_request()  # Exact fixed request and client write-half-close, including negatives.
    response = fixture.smb2_response(case)
    if response is None:
        time.sleep(_remaining(deadline))
        return
    if len(response) > fixture.SMB2_MAX_RESPONSE_BYTES:
        raise ValueError("smb2_fixture_response_limit")
    chunks = (bytes([value]) for value in response) if case == "smb2-fragmented" else (response,)
    for chunk in chunks:
        connection.settimeout(min(2, _remaining(deadline)))
        connection.sendall(chunk)
        if case == "smb2-fragmented":
            time.sleep(min(0.002, _remaining(deadline)))
    # The owner closes; opaque peer bytes never request an authentication step.
