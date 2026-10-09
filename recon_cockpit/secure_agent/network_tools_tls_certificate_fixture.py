"""Owned TLS 1.3 certificate exchange, fixed SNI, and no application session.

The negative-case progress counter attests only a bounded ClientHello prefix;
the complete-case counter additionally requires TLS 1.3 and clean close_notify.
Neither counter by itself attests the client's trust or hostname verification.
"""

import hashlib
import importlib.util
import math
import os
from pathlib import Path
import socket
import ssl
import time

if __package__:
    from . import network_tools_fixture as fixture
    from . import network_tools_tls_certificate_material as material
else:
    def _load(name, filename):
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    fixture = _load("tls_certificate_public_fixture", "network_tools_fixture.py")
    material = _load("tls_certificate_owner_material", "network_tools_tls_certificate_material.py")


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if not math.isfinite(remaining) or remaining <= 0:
        raise ValueError("tls_certificate_fixture_deadline")
    return remaining


def validate_client_hello_prefix(prefix):
    # This is intentionally a prefix check, not a full ClientHello parser.
    # TLS consumes the original record after MSG_PEEK. The one-record form and
    # legacy record version pin this fixture to the reviewed OpenSSL client.
    if (type(prefix) is not bytes
            or len(prefix) != fixture.TLS_CERTIFICATE_CLIENT_HELLO_PREFIX_BYTES
            or prefix[:3] != b"\x16\x03\x01" or prefix[5] != 1):
        raise ValueError("tls_certificate_fixture_client_hello_prefix")
    record_length = int.from_bytes(prefix[3:5], "big")
    message_length = int.from_bytes(prefix[6:9], "big")
    if (not 45 <= record_length <= fixture.TLS_CERTIFICATE_MAX_CLIENT_HELLO_BYTES - 5
            or message_length != record_length - 4):
        raise ValueError("tls_certificate_fixture_client_hello_length")
    return prefix


def _peek_client_hello(connection, deadline):
    while True:
        connection.settimeout(min(2, _remaining(deadline)))
        prefix = connection.recv(fixture.TLS_CERTIFICATE_CLIENT_HELLO_PREFIX_BYTES, socket.MSG_PEEK)
        if not prefix:
            raise ValueError("tls_certificate_fixture_client_hello_eof")
        if len(prefix) == fixture.TLS_CERTIFICATE_CLIENT_HELLO_PREFIX_BYTES:
            return validate_client_hello_prefix(prefix)
        # MSG_PEEK must not consume partial bytes before SSL wraps the socket.
        # A partial, disconnected record therefore times out instead of being
        # confused with a complete TLS request; the pause prevents a busy loop.
        time.sleep(min(0.005, _remaining(deadline)))


def _server_name(connection, server_name, context):
    if server_name != fixture.TLS_NAME:
        return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
    return None


def configure_context(context):
    """Apply the reviewed protocol/SNI/ticket boundary to an owner context."""
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.num_tickets = 0
    context.sni_callback = _server_name
    return context


def tls_context(case):
    certificate = material.certificate_for_case(case)
    if hashlib.sha256(certificate).hexdigest() != fixture.TLS_CERTIFICATE_CERT_SHA256[case]:
        raise ValueError("tls_certificate_fixture_material_mismatch")
    descriptors = []
    try:
        for label, data in (("public-c15-cert", certificate), ("public-c15-key", material.SERVER_KEY_PEM)):
            descriptor = os.memfd_create(label, os.MFD_CLOEXEC)
            descriptors.append(descriptor)
            if os.write(descriptor, data) != len(data):
                raise ValueError("tls_certificate_fixture_material_truncated")
        context = configure_context(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))
        context.load_cert_chain(*(f"/proc/self/fd/{descriptor}" for descriptor in descriptors))
        return context
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def serve(connection, *, case, deadline, context, on_request):
    # Validate case before touching the connection or reporting progress.
    material.certificate_for_case(case)
    _peek_client_hello(connection, deadline)
    complete = case in fixture.TLS_CERTIFICATE_COMPLETE_CASES
    if not complete:
        on_request()
    if case == "tls-cert-stalled":
        time.sleep(_remaining(deadline))
        return
    if case == "tls-cert-malformed":
        connection.settimeout(min(2, _remaining(deadline)))
        connection.sendall(fixture.TLS_MALFORMED_BYTES)
        return
    connection.settimeout(min(2, _remaining(deadline)))
    secured = context.wrap_socket(connection, server_side=True, suppress_ragged_eofs=False)
    try:
        if secured.version() != "TLSv1.3":
            raise ValueError("tls_certificate_fixture_version")
        secured.settimeout(min(2, _remaining(deadline)))
        # Reject application bytes and ragged TCP EOF before counting complete.
        closed = secured.unwrap()
        try:
            if complete:
                on_request()
        finally:
            closed.close()
    finally:
        secured.close()
