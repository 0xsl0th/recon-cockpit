"""Pure finite ClientHello grammar shared by the owned peer and offline replay.

This module has no fixture, key, socket, TLS runtime or execution dependency.
It validates one complete record as data and grants no execution authority.
"""

import hashlib

VERSIONS = {"tls1": (0x0301, 0xC009),
            "tls1_1": (0x0302, 0xC009),
            "tls1_2": (0x0303, 0xC02B),
            "tls1_3": (0x0304, 0x1302)}
TLS_NAME = "harbordesk.test"
MAX_CLIENT_HELLO = 4096
COOKIE = b"T02-HRR-ONLY"


class _Reader:
    def __init__(self, raw):
        self.raw, self.position = raw, 0

    def take(self, length):
        if length < 0 or self.position + length > len(self.raw):
            raise ValueError("tls_posture_client_hello_length")
        start = self.position
        self.position += length
        return self.raw[start:self.position]

    def vector(self, width):
        return self.take(int.from_bytes(self.take(width), "big"))

    def done(self):
        if self.position != len(self.raw):
            raise ValueError("tls_posture_client_hello_trailing")


def validate_client_hello(raw, version, *, retry=False):
    """Validate the complete finite ClientHello, not just its record prefix."""
    if (type(raw) is not bytes or version not in VERSIONS or not 50 <= len(raw) <= MAX_CLIENT_HELLO
            or raw[0] != 22 or raw[1:3] not in (b"\x03\x01", b"\x03\x02", b"\x03\x03")
            or int.from_bytes(raw[3:5], "big") != len(raw) - 5
            or raw[5] != 1 or int.from_bytes(raw[6:9], "big") != len(raw) - 9):
        raise ValueError("tls_posture_client_hello_record")
    reader = _Reader(raw[9:])
    offered, cipher = VERSIONS[version]
    if int.from_bytes(reader.take(2), "big") != min(offered, 0x0303):
        raise ValueError("tls_posture_client_hello_version")
    random = reader.take(32)  # Randomness is opaque, fixed-size data.
    session = reader.vector(1)
    if len(session) > 32 or (version != "tls1_3" and session):
        raise ValueError("tls_posture_client_hello_session")
    suites = reader.vector(2)
    if not suites or len(suites) % 2:
        raise ValueError("tls_posture_client_hello_ciphers")
    values = [int.from_bytes(suites[i:i + 2], "big") for i in range(0, len(suites), 2)]
    if len(values) != len(set(values)) or cipher not in values or not set(values) <= {cipher, 0x00FF}:
        raise ValueError("tls_posture_client_hello_ciphers")
    if reader.vector(1) != b"\0":
        raise ValueError("tls_posture_client_hello_compression")
    extensions_reader = _Reader(reader.vector(2))
    reader.done()
    extensions = {}
    while extensions_reader.position < len(extensions_reader.raw):
        kind = int.from_bytes(extensions_reader.take(2), "big")
        value = extensions_reader.vector(2)
        if kind in extensions or kind not in {0, 10, 11, 13, 22, 23, 43, 44, 45, 51, 0xFF01}:
            raise ValueError("tls_posture_client_hello_extension")
        extensions[kind] = value
    expected_name = TLS_NAME.encode("ascii")
    expected_sni = (len(expected_name) + 3).to_bytes(2, "big") + b"\0" + len(expected_name).to_bytes(2, "big") + expected_name
    if extensions.get(0) != expected_sni or extensions.get(10) != b"\0\2\0\x17":
        raise ValueError("tls_posture_client_hello_name_group")
    for kind in (22, 23):
        if kind in extensions and extensions[kind] != b"":
            raise ValueError("tls_posture_client_hello_empty_extension")
    if 0xFF01 in extensions and extensions[0xFF01] != b"\0":
        raise ValueError("tls_posture_client_hello_renegotiation")
    if 11 in extensions:
        formats = _Reader(extensions[11])
        points = formats.vector(1)
        formats.done()
        if not points or points[0] != 0 or len(points) != len(set(points)) or not set(points) <= {0, 1, 2}:
            raise ValueError("tls_posture_client_hello_point_formats")
    if 13 in extensions:
        signatures = _Reader(extensions[13])
        algorithms = signatures.vector(2)
        signatures.done()
        if not algorithms or len(algorithms) % 2:
            raise ValueError("tls_posture_client_hello_signatures")
    if version == "tls1_3":
        if extensions.get(43) != b"\2\3\4" or 51 not in extensions or 13 not in extensions:
            raise ValueError("tls_posture_client_hello_supported_version")
        shares = _Reader(extensions[51])
        entries = _Reader(shares.vector(2))
        shares.done()
        if entries.take(2) != b"\0\x17":
            raise ValueError("tls_posture_client_hello_key_share")
        key = entries.vector(2)
        entries.done()
        if len(key) != 65 or key[0] != 4:
            raise ValueError("tls_posture_client_hello_key_share")
        cookie = len(COOKIE).to_bytes(2, "big") + COOKIE
        if (retry and extensions.get(44) != cookie) or (not retry and 44 in extensions):
            raise ValueError("tls_posture_client_hello_cookie")
        # The fixed OpenSSL client advertises only psk_dhe_ke even with
        # -no_ticket. Advertising this mode does not supply a PSK: extension
        # 41 (pre_shared_key), tickets, early data and resumptions stay refused.
        if 45 in extensions and extensions[45] != b"\1\1":
            raise ValueError("tls_posture_client_hello_psk_modes")
    elif any(kind in extensions for kind in (43, 44, 45, 51)) or retry:
        raise ValueError("tls_posture_client_hello_supported_version")
    return {"version": version, "session_id_hex": session.hex(), "cipher": cipher,
            "random_hex": random.hex(),
            "extension_types": sorted(extensions), "sha256": hashlib.sha256(raw).hexdigest()}
